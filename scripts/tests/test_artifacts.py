import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location("artifacts", Path(__file__).parents[1] / "verify-artifacts.py")
artifacts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(artifacts)


class ArtifactValidationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.version = "0.1.0"
        self.create_repository()

    def directory(self, suffix=""):
        name = artifacts.NAME + ("-" + suffix if suffix else "")
        return self.root / "com/maniramezan" / name / self.version, f"{name}-{self.version}"

    def create_repository(self):
        root_variants = []
        for target, extension in artifacts.PLATFORMS.items():
            directory, base = self.directory(target)
            directory.mkdir(parents=True)
            name = artifacts.NAME + ("-" + target if target else "")
            (directory / f"{base}.{extension}").write_bytes(b"binary")
            (directory / f"{base}.pom").write_text(f'''<project xmlns="http://maven.apache.org/POM/4.0.0">
                <groupId>com.maniramezan</groupId><artifactId>{name}</artifactId><version>{self.version}</version>
                <name>Keychain</name><description>Credentials</description><url>https://example.test</url>
                <licenses><license><name>MIT</name></license></licenses>
                <developers><developer><id>maintainer</id></developer></developers>
                <scm><connection>scm:git:example</connection></scm></project>''')
            for classifier, entry in (("sources", "Credentials.kt"), ("javadoc", "index.html")):
                with zipfile.ZipFile(directory / f"{base}-{classifier}.jar", "w") as archive:
                    archive.writestr(entry, "test content")
            if target == "jvm":
                self.write_classes(directory / f"{base}.jar", artifacts.JVM_CLASS_MAJOR)
            (directory / f"{base}.module").write_text(json.dumps({"variants": [{"files": [{"url": f"{base}.{extension}"}]}]}))
            if target:
                root_variants.append({"available-at": {"group": "com.maniramezan", "module": name, "version": self.version,
                    "url": f"../../{name}/{self.version}/{base}.module"}})
        directory, base = self.directory()
        (directory / f"{base}.module").write_text(json.dumps({"variants": root_variants}))

    @staticmethod
    def write_classes(path, major):
        with zipfile.ZipFile(path, "w") as jar:
            jar.writestr("Credentials.class", b"\xca\xfe\xba\xbe\x00\x00" + major.to_bytes(2, "big"))

    def test_complete_unsigned_repository(self):
        self.assertEqual(11, artifacts.verify(self.root, self.version))

    def test_missing_platform_binary_fails(self):
        directory, base = self.directory("iosarm64")
        (directory / f"{base}.klib").unlink()
        with self.assertRaisesRegex(ValueError, "Missing or empty"):
            artifacts.verify(self.root, self.version)

    def test_missing_root_variant_fails(self):
        directory, base = self.directory()
        path = directory / f"{base}.module"
        data = json.loads(path.read_text())
        data["variants"].pop()
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "Root metadata targets differ"):
            artifacts.verify(self.root, self.version)

    def test_signatures_required_for_staging(self):
        with self.assertRaisesRegex(ValueError, "Missing signature"):
            artifacts.verify(self.root, self.version, signed=True)

    def test_empty_javadoc_is_rejected(self):
        directory, base = self.directory("jvm")
        with zipfile.ZipFile(directory / f"{base}-javadoc.jar", "w"):
            pass
        with self.assertRaisesRegex(ValueError, "Empty API documentation"):
            artifacts.verify(self.root, self.version)

    def test_broken_file_reference_is_rejected(self):
        directory, base = self.directory("jvm")
        (directory / f"{base}.module").write_text(json.dumps({"variants": [{"files": [{"url": "missing.jar"}]}]}))
        with self.assertRaisesRegex(ValueError, "Broken metadata file reference"):
            artifacts.verify(self.root, self.version)

    def test_newer_jvm_bytecode_is_rejected(self):
        directory, base = self.directory("jvm")
        self.write_classes(directory / f"{base}.jar", 21 + 44)
        with self.assertRaisesRegex(ValueError, "must target Java 17"):
            artifacts.verify(self.root, self.version)

    def test_wrong_pom_version_is_rejected(self):
        directory, base = self.directory("jvm")
        path = directory / f"{base}.pom"
        path.write_text(path.read_text().replace("<version>0.1.0</version>", "<version>9.0.0</version>"))
        with self.assertRaisesRegex(ValueError, "Incorrect POM version"):
            artifacts.verify(self.root, self.version)
