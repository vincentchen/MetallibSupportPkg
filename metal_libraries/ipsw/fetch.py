"""
fetch.py: Fetch latest IPSW images for macOS
"""

import sys
import plistlib
import concurrent.futures
import packaging.version

from .manifest import MetallibSupportPkgManifest

from ..network import NetworkUtilities
from .. import __version__


def _log(msg: str) -> None:
    """Log to stderr to avoid polluting stdout (used for GITHUB_OUTPUT)"""
    print(msg, file=sys.stderr)


class FetchIPSW:

    def __init__(self, builds_to_ignore: list = [], os_versions: list = [15, 26], target: str = None) -> None:
        self._builds_to_ignore = builds_to_ignore
        self._os_versions = os_versions
        self._target = target
        self._version_ranges = [
            (packaging.version.parse(str(v)), packaging.version.parse(f"{v}.99.99"))
            for v in os_versions
        ]


    def _fetch_apple_db_items(self):
        """
        Get macOS installers from AppleDB
        """

        installers = [
            # "22F82": {
            #   url: "https://swcdn.apple.com/content/downloads/36/06/042-01917-A_B57IOY75IU/oocuh8ap7y8l8vhu6ria5aqk7edd262orj/InstallAssistant.pkg",
            #   version: "13.4.1",
            #   build: "22F82",
            # }
        ]

        _log(f"[IPSW Fetch] Querying AppleDB for macOS versions: {self._os_versions}")
        _log(f"[IPSW Fetch] Target: {self._target or 'latest unpublished build'}")
        _log(f"[IPSW Fetch] Builds to ignore (CI skip list): {self._builds_to_ignore}")

        apple_db = NetworkUtilities().get("https://api.appledb.dev/ios/macOS/main.json")
        if apple_db is None:
            _log("[IPSW Fetch] ERROR: Failed to fetch from AppleDB API")
            return []

        _log(f"[IPSW Fetch] Received {len(apple_db.json())} items from AppleDB")

        apple_db = apple_db.json()
        filtered_count = 0
        for item in apple_db:
            # Skip internal builds and RSR updates
            if item.get("internal") or item.get("rsr"):
                continue

            # Skip builds in ignore list
            if "build" not in item:
                filtered_count += 1
                continue

            if self._target:
                # An explicit target overrides the CI skip list, so a published
                # build can be rebuilt on demand.
                if not self._matches_target(item):
                    filtered_count += 1
                    continue
            elif item["build"] in self._builds_to_ignore:
                filtered_count += 1
                continue

            # Filter by version range
            try:
                version = packaging.version.parse(item["version"].split(" ")[0])
                if not any(lo <= version <= hi for lo, hi in self._version_ranges):
                    filtered_count += 1
                    continue
            except packaging.version.InvalidVersion:
                filtered_count += 1
                continue


            name = "macOS"
            if "appledbWebImage" in item:
                if "id" in item["appledbWebImage"]:
                    name += " " + item["appledbWebImage"]["id"]

            for source in item.get("sources", []):
                # OTAs are unified, so MacPro7,1 and VirtualMac2,1 will be in the device map
                # IPSWs are not, so we only check for VirtualMac2,1
                if "VirtualMac2,1" not in source.get("deviceMap", []):
                    continue

                if source["type"] not in ["ipsw", "ota"]:
                    continue

                for link in source.get("links", []):
                    if not link["active"]:
                        continue

                    installers.append(
                        {
                            "Name": name,
                            "Version": item["version"],
                            "Type": source["type"],
                            "Build": item["build"],
                            "URL": link["url"],
                            "Variant": "Beta" if (item.get("beta") or item.get("rc")) else "Public",
                            "Date": item["released"],
                            # OTAs generally have no hashes in AppleDB; plistlib cannot
                            # serialize None, so normalize to an empty string.
                            "Hash": source.get("hashes", {}).get("sha1") or "",
                        }
                    )
                    # IPSW links are interchangeable; one is enough. OTA links are
                    # not: AppleDB lists both full (~18 GB) and delta (~2-8 GB)
                    # assets for the same build, so collect them all and pick the
                    # full one later.
                    if source["type"] == "ipsw":
                        break

        _log(f"[IPSW Fetch] Filtered {filtered_count} items (internal/rsr/ignored/version mismatch)")
        _log(f"[IPSW Fetch] Found {len(installers)} valid installers")

        # Deduplicate builds
        installers_by_build = {}
        for installer in installers:
            installers_by_build.setdefault(installer["Build"], []).append(installer)

        for build, installer_variants in installers_by_build.items():
            # Prefer IPSW over OTA (IPSW is a complete image, OTA may have access issues)
            installer_variants.sort(key=lambda x: (x["Type"] != "ipsw", x["Variant"] != "Public"))

        deduplicated = [variants[0] for variants in installers_by_build.values()]
        deduplicated.sort(key=lambda x: (x["Variant"] == "Public", x["Type"] == "ipsw", x["Date"]), reverse=True)

        _log(f"[IPSW Fetch] After deduplication: {len(deduplicated)} unique builds")

        # Filter out OTAs - only keep IPSW for reliable downloads
        ipsw_only = [x for x in deduplicated if x["Type"] == "ipsw"]
        _log(f"[IPSW Fetch] IPSW candidates: {len(ipsw_only)}")

        if ipsw_only:
            best = ipsw_only[0]
            _log(f"[IPSW Fetch] Best match: {best['Name']} {best['Version']} ({best['Build']}) - {best['Type']} - {best['Variant']}")
            return ipsw_only

        if deduplicated:
            _log("[IPSW Fetch] WARNING: No IPSW available, falling back to OTA")
            best = deduplicated[0]
            # AppleDB lists many OTA assets for a build: one full update and
            # several deltas. Deltas cannot be used standalone, so pick the
            # largest asset.
            best = self._pick_full_ota(installers_by_build.get(best["Build"], [best]))
            _log(f"[IPSW Fetch] Best match: {best['Name']} {best['Version']} ({best['Build']}) - {best['Type']} - {best['Variant']}")
            return [best]

        return deduplicated


    def _matches_target(self, item: dict) -> bool:
        """
        Check whether an AppleDB entry matches the requested version or build.

        Accepts either a macOS version (e.g. "26.7.1") or a build (e.g. "25G241").
        """
        target = self._target.strip()
        return (
            target == item.get("build", "")
            or target == item.get("version", "")
            or item.get("version", "").startswith(target + " ")
        )


    def _pick_full_ota(self, variants: list[dict]) -> dict:
        """
        Pick the full OTA asset for a build.

        AppleDB lists multiple OTA assets per build (a full update plus delta
        updates). Deltas are much smaller and cannot be used to build a
        standalone MetallibSupportPkg, so choose the largest asset.
        """
        unique = {}
        for variant in variants:
            if variant["Type"] != "ota":
                continue
            # AppleDB lists the same asset twice (https and http); keep one and
            # prefer the secure URL.
            name = variant["URL"].rsplit("/", 1)[-1]
            current = unique.get(name)
            if current is None or (
                current["URL"].startswith("http://") and variant["URL"].startswith("https://")
            ):
                unique[name] = variant

        candidates = list(unique.values())
        if len(candidates) <= 1:
            return candidates[0] if candidates else variants[0]

        def content_length(variant: dict) -> int:
            return NetworkUtilities(variant["URL"]).content_length()

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            sizes = list(pool.map(content_length, candidates))

        ranked = sorted(zip(candidates, sizes), key=lambda item: item[1], reverse=True)
        for variant, size in ranked[:5]:
            _log(f"[IPSW Fetch] OTA candidate: {size / 1e9:.2f} GB - {variant['URL']}")

        return ranked[0][0]


    def _save_info(self, info: dict) -> None:
        """
        Save the build info to Info.plist
        """
        info["MetallibSupportPkgVersion"] = __version__
        with open("Info.plist", "wb") as file:
            plistlib.dump(info, file)


    def fetch(self) -> dict:
        """
        Fetch latest macOS installer
        """
        _log("[IPSW Fetch] Starting IPSW fetch...")
        result = self._fetch_apple_db_items()
        if len(result) == 0:
            _log("[IPSW Fetch] ERROR: No valid IPSW found (all builds filtered or AppleDB empty)")
            return {}
        MetallibSupportPkgManifest(result[0]).update_manifest()
        self._save_info(result[0])
        _log(f"[IPSW Fetch] SUCCESS: Selected {result[0]['Version']} ({result[0]['Build']})")
        _log(f"[IPSW Fetch] URL: {result[0]['URL'][:80]}...")
        return result[0]["URL"]