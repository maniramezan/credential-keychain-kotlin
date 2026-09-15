#!/usr/bin/env python3
"""Validate the complete KMP filesystem repository before testing a consumer or staging."""
import argparse
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET
import zipfile

# Every published module; each one publishes the same KMP targets.
ARTIFACTS = ("credential-keychain-kotlin", "credential-keychain-kotlin-biometric")
PLATFORMS = {
    "": "jar", "jvm": "jar", "android": "aar",
    **{target: "klib" for target in (
        "iosarm64", "iossimulatorarm64", "macosarm64",
        "tvosarm64", "tvossimulatorarm64", "watchosarm64",
        "watchosdevicearm64", "watchossimulatorarm64",
    )},
}
NS = {"m": "http://maven.apache.org/POM/4.0.0"}
JVM_VERSION = 17
JVM_CLASS_MAJOR = JVM_VERSION + 44


def version_from_properties(path=Path("gradle.properties")):
    for line in path.read_text().splitlines():
        if line.startswith("VERSION_NAME="):
            version = line.split("=", 1)[1].strip()
            if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?", version):
                raise ValueError("VERSION_NAME must be a semantic version")
            return version
    raise ValueError("VERSION_NAME is missing")


def verify(repository, version, signed=False, names=ARTIFACTS):
    repository = Path(repository).resolve()
    return sum(verify_module(repository, name, version, signed) for name in names)


def verify_module(repository, name, version, signed):
    expected = {name + ("-" + target if target else "") for target in PLATFORMS}
    for target, extension in PLATFORMS.items():
        artifact = name + ("-" + target if target else "")
        directory = repository / "com/maniramezan" / artifact / version
        base = f"{artifact}-{version}"
        paths = [directory / (base + suffix) for suffix in
                 (f".{extension}", ".pom", ".module", "-sources.jar", "-javadoc.jar")]
        for path in paths:
            if not path.is_file() or path.stat().st_size == 0:
                raise ValueError(f"Missing or empty artifact: {path}")
            signature = path.with_name(path.name + ".asc")
            if signed and (not signature.is_file() or signature.stat().st_size == 0):
                raise ValueError(f"Missing signature: {path}")
        pom = ET.parse(directory / (base + ".pom")).getroot()
        for field, value in (("groupId", "com.maniramezan"), ("artifactId", artifact), ("version", version)):
            if pom.findtext("m:" + field, namespaces=NS) != value:
                raise ValueError(f"Incorrect POM {field}: {artifact}")
        for field in ("name", "description", "url", "licenses/license/name", "developers/developer/id", "scm/connection"):
            xpath = "/".join("m:" + part for part in field.split("/"))
            if not pom.findtext(xpath, namespaces=NS):
                raise ValueError(f"Missing POM {field}: {artifact}")
        with zipfile.ZipFile(directory / (base + "-sources.jar")) as sources:
            if not any(entry.endswith(".kt") for entry in sources.namelist()):
                raise ValueError(f"Empty Kotlin sources: {artifact}")
        with zipfile.ZipFile(directory / (base + "-javadoc.jar")) as docs:
            if not any(entry.endswith("index.html") for entry in docs.namelist()):
                raise ValueError(f"Empty API documentation: {artifact}")
        metadata = json.loads((directory / (base + ".module")).read_text())
        for variant in metadata.get("variants", []):
            for item in variant.get("files", []):
                file = (directory / item["url"]).resolve()
                if not file.is_relative_to(repository) or not file.is_file():
                    raise ValueError(f"Broken metadata file reference: {artifact}/{item['url']}")
            available = variant.get("available-at")
            if available:
                if available["group"] != "com.maniramezan" or available["version"] != version:
                    raise ValueError(f"Unexpected variant coordinates: {artifact}")
                file = (directory / available["url"]).resolve()
                if not file.is_relative_to(repository) or not file.is_file():
                    raise ValueError(f"Broken variant reference: {artifact}")
        if target == "jvm":
            # Kotlin does not publish org.gradle.jvm.version, so inspect the class file versions.
            with zipfile.ZipFile(directory / (base + ".jar")) as jar:
                majors = {int.from_bytes(jar.read(entry)[6:8], "big") for entry in jar.namelist() if entry.endswith(".class")}
            if not majors or max(majors) > JVM_CLASS_MAJOR:
                raise ValueError(f"JVM classes must target Java {JVM_VERSION}: found class versions {sorted(majors)}")
        if not target:
            actual = {v["available-at"]["module"] for v in metadata.get("variants", []) if "available-at" in v}
            if actual != expected - {name}:
                raise ValueError(f"Root metadata targets differ: missing={expected - {name} - actual}, extra={actual - expected}")
    return len(expected)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", type=Path)
    parser.add_argument("--signed", action="store_true")
    args = parser.parse_args()
    count = verify(args.repository, version_from_properties(), args.signed)
    print(f"Verified {count} KMP publications across {len(ARTIFACTS)} modules, with sources, documentation, and metadata references.")
