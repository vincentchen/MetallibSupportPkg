"""
extract.py: Extract System Volume from IPSW images
"""

import zipfile
import tempfile
import plistlib
import subprocess
import platform
import lzma
import re
import struct
import sys

from pathlib import Path

from ..utils.log import log


class IPSWExtract:
    def __init__(self, ipsw: str) -> None:
        self._ipsw = Path(ipsw)

    def _decrypt_aea(self, input: Path) -> str:
        """
        Decrypt an AEA file.
        """
        arch=platform.machine()
        output = input.with_suffix("")
        if arch=="x86_64":
            aea_bin = Path(__file__).resolve().parent / "bins" / "aastuff"
        else:
            aea_bin = Path(__file__).resolve().parent / "bins" / "aastuff-arm"
        if not aea_bin.exists():
            raise FileNotFoundError(f"{aea_bin} not found")

        result = subprocess.run(
            [
                aea_bin,
                "--input",
                input,
                "--output",
                output,
                "--decrypt-only",
                "--network",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            log(result)
            raise Exception(f"Failed to decrypt {input}")

        return output

    def _extract_system_volume(self) -> str:
        """
        Extract the system volume from an IPSW file.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            with zipfile.ZipFile(self._ipsw, "r") as zip_ref:
                zip_ref.extractall(tmp_dir)

            with open(f"{tmp_dir}/BuildManifest.plist", "rb") as f:
                build_manifest = plistlib.load(f)

            system_image_path = None
            for build_identity in build_manifest["BuildIdentities"]:
                if build_identity["Ap,ProductType"] == "VirtualMac2,1":
                    system_image_path = build_identity["Manifest"]["OS"]["Info"]["Path"]
                    break

            if not system_image_path:
                raise Exception("Failed to find system image path")

            system_image_path = Path(tmp_dir, system_image_path)

            if system_image_path.suffix == ".aea":
                system_image_path = self._decrypt_aea(system_image_path)

            # Copy from tmp_dir to cwd
            result = subprocess.run(
                ["/bin/cp", "-cr", system_image_path, "."],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                log(result)
                raise Exception(f"Failed to copy {system_image_path}")

        return system_image_path.name

    def extract(self) -> str:
        """
        Extract the system volume from an IPSW file.
        """
        return self._extract_system_volume()


class OTAExtract:
    def __init__(self, ota: str) -> None:
        self._ota = Path(ota)

    def _decrypt_aea(self, input: Path, output: Path) -> str:
        """
        Decrypt an AEA file.
        """
        aea_bin = Path(__file__).resolve().parent / "bins" / "aastuff"
        if not aea_bin.exists():
            raise FileNotFoundError(f"{aea_bin} not found")

        result = subprocess.run(
            [
                aea_bin,
                "--input",
                input,
                "--output",
                output,
                "--network",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            log(result)
            raise Exception(f"Failed to decrypt {input}")

        return output

    def _decode_pbzx(self, source, output: Path) -> bool:
        """
        Decode Apple's pbzx stream used by OTA payloads.

        OTA payload files are pbzx-wrapped Apple Archives (YAA1), while
        /usr/bin/aa only understands the Apple Archive itself. A pbzx stream is
        a 12-byte header followed by XZ-compressed chunks, each prefixed with
        the uncompressed and compressed sizes.

        The stream is decoded straight to disk because a single payload can
        expand to well over a gigabyte.

        Parameters:
        - source: binary file object positioned at the start of the payload
        - output: path the decoded Apple Archive is written to

        Returns:
        - True if the payload was a pbzx stream, False otherwise
        """
        if source.read(4) != b"pbzx":
            return False

        source.read(8)  # Global flags (uncompressed chunk size)

        with open(output, "wb") as file:
            while True:
                header = source.read(16)
                if len(header) < 16:
                    break

                _, compressed_size = struct.unpack(">QQ", header)
                decompressor = lzma.LZMADecompressor()
                remaining = compressed_size
                while remaining > 0:
                    chunk = source.read(min(remaining, 1 << 20))
                    if not chunk:
                        raise Exception("Unexpected end of pbzx stream")
                    remaining -= len(chunk)
                    file.write(decompressor.decompress(chunk))

        return True


    def _extract_archive(self, archive: Path, output_dir: Path) -> None:
        """
        Extract all metallib files from a single Apple Archive.
        """
        result = subprocess.run(
            [
                "/usr/bin/aa",
                "extract",
                "-i",
                str(archive),
                "-d",
                str(output_dir),
                "-include-regex",
                ".*metallib.*",
                "-enable-dedup"
            ],
        )
        if result.returncode != 0:
            log(result)
            raise Exception(f"Failed to extract {archive}")


    def _extract_system_volume(self) -> str:
        """
        Extract the system volume from an OTA file.
        """

        output_dir = Path("root")
        links_txt = ""
        failures = []
        extracted = 0

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)

            if self._ota.suffix == ".aea":
                archive = tmp_path / "payload.aar"
                self._decrypt_aea(self._ota, archive)
                self._extract_archive(archive, output_dir)
            else:
                with zipfile.ZipFile(self._ota, "r") as zip_ref:
                    names = zip_ref.namelist()

                    # SystemVersion.plist is needed by MetallibFetch to name the
                    # output directory (<version>-<build>). The OTA zip carries a
                    # copy at AssetData/boot, so use it instead of relying on the
                    # extraction filter below.
                    version_name = "AssetData/boot/SystemVersion.plist"
                    if version_name in names:
                        version_dest = output_dir / "System/Library/CoreServices/SystemVersion.plist"
                        version_dest.parent.mkdir(parents=True, exist_ok=True)
                        version_dest.write_bytes(zip_ref.read(version_name))

                    # Extract all payload files in AssetData/payloadv2, as well as
                    # the data payload. Payloads are pbzx-wrapped Apple Archives.
                    payload_prefix = "AssetData/payloadv2/"
                    payload_names = sorted(
                        name for name in names
                        if name.startswith(payload_prefix)
                        and re.fullmatch(r"payload\.\d+", name.rsplit("/", 1)[-1])
                    )
                    data_payload = payload_prefix + "data_payload"
                    if data_payload in names:
                        payload_names.append(data_payload)

                    for index, name in enumerate(payload_names, 1):
                        archive = tmp_path / "payload.aar"
                        print(f"[OTA Extract] Payload {index}/{len(payload_names)}: {name}", file=sys.stderr)

                        try:
                            with zip_ref.open(name) as source:
                                if not self._decode_pbzx(source, archive):
                                    # data_payload and similar placeholders are not archives
                                    continue

                            with open(archive, "rb") as file:
                                if file.read(4) not in (b"AA01", b"YAA1"):
                                    continue

                            self._extract_archive(archive, output_dir)
                            extracted += 1
                        except Exception as error:
                            # A single unreadable payload should not abort the whole
                            # build; metallibs are spread over many payloads.
                            print(f"[OTA Extract] WARNING: {error}", file=sys.stderr)
                            failures.append(name)
                        finally:
                            archive.unlink(missing_ok=True)

                    if payload_names and extracted == 0:
                        raise Exception(f"Failed to extract every OTA payload: {failures}")
                    if failures:
                        print(f"[OTA Extract] WARNING: skipped {len(failures)} payload(s): {failures}", file=sys.stderr)

                    links_name = payload_prefix + "links.txt"
                    if links_name in names:
                        links_txt = zip_ref.read(links_name).decode("utf-8")

            # Handle links.txt
            links = {}
            last_target = None
            for line in links_txt.splitlines():
                if not line.strip():
                    continue
                if line[0] == "=":
                    last_target = line[1:].strip()
                    links.setdefault(last_target, [])
                elif line[0] == "+":
                    assert last_target
                    links[last_target].append(line[1:].strip())

            for target, target_links in links.items():
                if "metallib" not in target:
                    continue
                target_path = output_dir / target
                if not target_path.exists():
                    continue
                for link in target_links:
                    link_path = output_dir / link
                    link_path.parent.mkdir(parents=True, exist_ok=True)
                    subprocess.check_call(
                        ["/bin/cp", "-c", str(target_path), str(link_path)]
                    )

        return str(output_dir)

    def extract(self) -> str:
        """
        Extract the system volume from an IPSW file.
        """
        return self._extract_system_volume()
