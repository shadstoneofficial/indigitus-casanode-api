from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "package/p1_policy.py"
SPEC = importlib.util.spec_from_file_location("p1_policy", POLICY_PATH)
assert SPEC and SPEC.loader
p1 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(p1)
ALLOWLIST = ROOT / "package/p1-allowlist.json"


def tar_bytes(entries: list[tuple[str, str, bytes]]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, kind, data in entries:
            member = tarfile.TarInfo(name)
            member.uid = 0
            member.gid = 0
            member.uname = "root"
            member.gname = "root"
            member.mode = 0o755 if kind == "directory" else 0o644
            if kind == "directory":
                member.type = tarfile.DIRTYPE
                archive.addfile(member)
            elif kind == "symlink":
                member.type = tarfile.SYMTYPE
                member.linkname = "target"
                archive.addfile(member)
            else:
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
    return output.getvalue()


class AllowlistTests(unittest.TestCase):
    def test_allowlist_is_closed_and_contains_no_forbidden_member(self) -> None:
        document = p1.load_allowlist(ALLOWLIST)
        members = document["members"]
        self.assertGreater(len(members), 70)
        self.assertEqual(len({(item["scope"], item["path"]) for item in members}), len(members))
        for item in members:
            self.assertNotIn("*", item["source"] or "")
            if item["type"] == "file":
                self.assertFalse(p1.path_is_forbidden(item["path"]), item["path"])
        self.assertNotIn(("control", "control.bak"), p1.member_map(document))

    def test_duplicate_and_traversal_members_fail(self) -> None:
        document = json.loads(ALLOWLIST.read_text())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "allowlist.json"
            document["members"].append(dict(document["members"][0]))
            path.write_text(json.dumps(document))
            with self.assertRaises(p1.PolicyError):
                p1.load_allowlist(path)
            document = json.loads(ALLOWLIST.read_text())
            document["members"][1]["path"] = "../control"
            path.write_text(json.dumps(document))
            with self.assertRaises(p1.PolicyError):
                p1.load_allowlist(path)

    def test_device_or_symlink_member_is_not_allowlistable(self) -> None:
        document = json.loads(ALLOWLIST.read_text())
        document["members"][1]["type"] = "device"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "allowlist.json"
            path.write_text(json.dumps(document))
            with self.assertRaises(p1.PolicyError):
                p1.load_allowlist(path)


class SecretScannerTests(unittest.TestCase):
    def test_pem_and_openssh_markers_are_rejected_without_echoing_input(self) -> None:
        markers = (
            b"-----BEGIN " + b"PRIVATE KEY-----",
            b"-----BEGIN " + b"OPENSSH PRIVATE KEY-----",
            b"-----BEGIN " + b"CERTIFICATE-----",
        )
        for marker in markers:
            with self.subTest(marker=marker[:20]):
                with self.assertRaises(p1.PolicyError) as caught:
                    p1.scan_member("safe/synthetic.txt", b"harmless-prefix\n" + marker + b"\nsynthetic-only")
                self.assertNotIn("harmless-prefix", str(caught.exception))
                self.assertNotIn("synthetic-only", str(caught.exception))

    def test_synthetic_non_text_pkcs8_shape_is_rejected(self) -> None:
        # Structurally key-shaped DER using tiny synthetic values; not a usable key.
        synthetic = bytes.fromhex("300a02010030020600040100")
        self.assertEqual(p1.forbidden_content_class(synthetic), "der-private-key")

    def test_private_key_certificate_and_retired_paths_are_rejected(self) -> None:
        for path in ("x/identity.key", "x/public.crt", "x/certs/value", "x/characteristics/old.js", "x/ble/old.js"):
            with self.subTest(path=path):
                self.assertTrue(p1.path_is_forbidden(path))


class SourcePolicyTests(unittest.TestCase):
    def make_committed_source(self) -> tuple[Path, str, str]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        repo = Path(temporary.name) / "source"
        repo.mkdir()
        environment = os.environ | {
            "GIT_AUTHOR_NAME": "P1 Synthetic Test",
            "GIT_AUTHOR_EMAIL": "p1-test.invalid@example.invalid",
            "GIT_COMMITTER_NAME": "P1 Synthetic Test",
            "GIT_COMMITTER_EMAIL": "p1-test.invalid@example.invalid",
        }

        def git(*args: str) -> str:
            completed = subprocess.run(
                ["git", *args], cwd=repo, env=environment, check=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            return completed.stdout.strip()

        git("init", "--quiet")
        (repo / "source.txt").write_text("historical base\n")
        git("add", "source.txt")
        git("commit", "--quiet", "-m", "synthetic base")
        base_commit = git("rev-parse", "HEAD^{commit}")
        base_tree = git("rev-parse", "HEAD^{tree}")
        (repo / "source.txt").write_text("clean committed candidate\n")
        git("add", "source.txt")
        git("commit", "--quiet", "-m", "synthetic candidate")
        candidate_commit = git("rev-parse", "HEAD^{commit}")
        candidate_tree = git("rev-parse", "HEAD^{tree}")
        base_patch = mock.patch.object(p1, "EXPECTED_BASE_COMMIT", base_commit)
        tree_patch = mock.patch.object(p1, "EXPECTED_BASE_TREE", base_tree)
        base_patch.start()
        tree_patch.start()
        self.addCleanup(base_patch.stop)
        self.addCleanup(tree_patch.stop)
        return repo, candidate_commit, candidate_tree

    def test_clean_committed_exact_source_passes_detached(self) -> None:
        repo, commit, tree = self.make_committed_source()
        subprocess.run(["git", "checkout", "--quiet", "--detach", commit], cwd=repo, check=True)
        self.assertEqual(p1.validate_release_source(repo, commit, tree), (commit, tree))

    def test_dirty_source_fails(self) -> None:
        repo, commit, tree = self.make_committed_source()
        (repo / "source.txt").write_text("dirty tracked content\n")
        with self.assertRaises(p1.PolicyError):
            p1.validate_release_source(repo, commit, tree)

    def test_wrong_expected_commit_fails(self) -> None:
        repo, _commit, tree = self.make_committed_source()
        with self.assertRaises(p1.PolicyError):
            p1.validate_release_source(repo, "0" * 40, tree)

    def test_wrong_expected_tree_fails(self) -> None:
        repo, commit, _tree = self.make_committed_source()
        with self.assertRaises(p1.PolicyError):
            p1.validate_release_source(repo, commit, "0" * 40)

    def test_missing_or_mutable_expected_identity_fails(self) -> None:
        repo, commit, tree = self.make_committed_source()
        for expected_commit, expected_tree in ((None, tree), (commit, None), ("HEAD", tree)):
            with self.subTest(commit=expected_commit, tree=expected_tree):
                with self.assertRaises(p1.PolicyError):
                    p1.validate_release_source(repo, expected_commit, expected_tree)

    def test_uncommitted_release_input_fails(self) -> None:
        repo, commit, tree = self.make_committed_source()
        (repo / "uncommitted.txt").write_text("uncommitted release input\n")
        with self.assertRaises(p1.PolicyError):
            p1.validate_release_source(repo, commit, tree)

    def test_clean_source_export_has_bounded_identity(self) -> None:
        repo, commit, tree = self.make_committed_source()
        with tempfile.TemporaryDirectory() as directory:
            export = Path(directory) / "source"
            identity = Path(directory) / "identity.json"
            p1.export_source(repo, export, identity, commit, tree)
            record = json.loads(identity.read_text())
            self.assertTrue(record["source_export_clean"])
            self.assertEqual(record["base_commit"], p1.EXPECTED_BASE_COMMIT)
            self.assertEqual(record["base_tree"], p1.EXPECTED_BASE_TREE)
            self.assertEqual(record["candidate_commit"], commit)
            self.assertEqual(record["candidate_tree"], tree)
            self.assertRegex(record["candidate_source_sha256"], r"^[0-9a-f]{64}$")
            self.assertFalse((export / ".git").exists())
            self.assertEqual((export / "source.txt").read_text(), "clean committed candidate\n")

    def test_forbidden_shared_ca_reference_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "app/src"
            source.mkdir(parents=True)
            (source / "synthetic.ts").write_text("const forbidden = '" + "ca" + ".key';")
            with self.assertRaises(p1.PolicyError):
                p1.validate_shared_ca_references(root)

    def test_current_source_has_no_shared_ca_branch(self) -> None:
        p1.validate_shared_ca_references(ROOT)
        source = (ROOT / "app/src/utils/certificate.ts").read_text()
        for term in ("caKeyPath", "caCertPath", "privateKeyFromPem"):
            self.assertNotIn(term, source)

    def test_compiled_allowlist_rejects_retired_or_extra_output(self) -> None:
        document = p1.load_allowlist(ALLOWLIST)
        expected = p1.expected_compiled_paths(document)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dist = root / "app/dist"
            for relative in expected:
                path = dist / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("// harmless synthetic output\n")
            p1.validate_compiled(root, document)
            stale = dist / "characteristics/retired.js"
            stale.parent.mkdir()
            stale.write_text("// stale synthetic marker\n")
            with self.assertRaises(p1.PolicyError):
                p1.validate_compiled(root, document)


class ToolchainAndArchiveTests(unittest.TestCase):
    def test_only_exact_immutable_image_is_accepted(self) -> None:
        p1.validate_build_reference(p1.EXPECTED_BUILD_IMAGE)
        for reference in ("node" + ":latest", "node:26", "", "node@sha256:" + "0" * 64):
            with self.subTest(reference=reference):
                with self.assertRaises(p1.PolicyError):
                    p1.validate_build_reference(reference)

    def test_duplicate_archive_entry_is_rejected(self) -> None:
        raw = tar_bytes([("./", "directory", b""), ("./same", "file", b"one"), ("./same", "file", b"two")])
        with self.assertRaises(p1.PolicyError):
            p1.inspect_tar(raw, "data")

    def test_special_archive_entry_is_rejected(self) -> None:
        raw = tar_bytes([("./", "directory", b""), ("./link", "symlink", b"")])
        with self.assertRaises(p1.PolicyError):
            p1.inspect_tar(raw, "data")

    def test_build_entrypoints_pin_toolchain_clean_output_and_npm_ci(self) -> None:
        host = (ROOT / "deb-build.sh").read_text()
        build = (ROOT / "package/build.sh").read_text()
        compose = (ROOT / "docker-compose.build.yml").read_text()
        self.assertIn(p1.EXPECTED_BUILD_IMAGE, host)
        self.assertIn(p1.EXPECTED_BUILD_IMAGE, compose)
        self.assertNotIn("node" + ":latest", host + compose)
        self.assertIn("npm ci", build)
        self.assertLess(build.index('find "$DIST_DIR" -mindepth 1 -delete'), build.index("npm ci"))
        self.assertNotIn("control.bak", build)
        self.assertIn("P1_EXPECTED_CANDIDATE_COMMIT", host)
        self.assertIn("P1_EXPECTED_CANDIDATE_TREE", host)
        self.assertNotIn("branch --show-current", (ROOT / "package/p1_policy.py").read_text())


class ProvenanceTests(unittest.TestCase):
    def valid_provenance(self) -> dict:
        return {
            "schema": p1.PROVENANCE_SCHEMA,
            "source": {
                "base_commit": p1.EXPECTED_BASE_COMMIT,
                "base_tree": p1.EXPECTED_BASE_TREE,
                "candidate_commit": "5" * 40,
                "candidate_tree": "6" * 40,
                "candidate_source_sha256": "1" * 64,
                "source_export_clean": True,
            },
            "build": {
                "image_digest": p1.EXPECTED_BUILD_IMAGE,
                "source_date_epoch": 1780346568,
                "lockfile_sha256": "2" * 64,
                "allowlist_sha256": "3" * 64,
            },
            "package": {
                "name": "casanode-api",
                "version": "2.0.0-alpha7",
                "architecture": "all",
                "payload_manifest_sha256_excluding_provenance": "4" * 64,
                "final_deb_sha256_evidence": "external-build-result-json",
            },
        }

    def test_complete_provenance_passes(self) -> None:
        p1.validate_provenance_document(self.valid_provenance())

    def test_missing_provenance_dimension_fails(self) -> None:
        document = self.valid_provenance()
        del document["build"]["lockfile_sha256"]
        with self.assertRaises(p1.PolicyError):
            p1.validate_provenance_document(document)

    def test_final_deb_hash_uses_non_self_referential_build_evidence(self) -> None:
        document = self.valid_provenance()
        document["package"]["final_deb_sha256_evidence"] = "embedded-placeholder"
        with self.assertRaises(p1.PolicyError):
            p1.validate_provenance_document(document)


if __name__ == "__main__":
    unittest.main()
