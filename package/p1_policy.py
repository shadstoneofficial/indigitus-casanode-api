#!/usr/bin/env python3
"""Fail-closed P1 source export, package staging, and archive validation."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile
from typing import Any, Iterable


SCHEMA = "indigitus.casanode-api.package-allowlist.v1"
PROVENANCE_SCHEMA = "indigitus.casanode-api.package-provenance.v1"
RESULT_SCHEMA = "indigitus.casanode-api.package-build-result.v1"
EXPECTED_BASE_COMMIT = "fa3a9cc3ffde779beb880b4a31be4bf673421ab8"
EXPECTED_BASE_TREE = "7dd9b2bf3bb00a28c009410e040ee206ad3370d2"
EXPECTED_BUILD_IMAGE = "node@sha256:bde0dae02f2b12d2bce5ee72b2432f0e511767b7b2dc4dd3b064df11ae422fee"
PROVENANCE_MEMBER = "usr/share/doc/casanode-api/build-provenance.json"

FORBIDDEN_SUFFIXES = {
    ".key", ".pem", ".crt", ".cer", ".p12", ".pfx", ".pkcs8",
    ".jks", ".keystore", ".der",
}
FORBIDDEN_PEM_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN CERTIFICATE-----",
)
FORBIDDEN_SHARED_CA_TERMS = (
    b"ca.key", b"ca.crt", b"caKeyPath", b"caCertPath", b"CERTS_DIR",
    b"getCertsDir", b"privateKeyFromPem",
)
RETIRED_COMPONENTS = {"certs", "characteristics", "ble"}


class PolicyError(RuntimeError):
    """A bounded policy failure safe to show to an operator."""


def fail(message: str) -> None:
    raise PolicyError(message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("utf-8")


def write_json(path: Path, value: Any) -> None:
    path.write_bytes(canonical_json(value))


def run_checked(argv: list[str], cwd: Path | None = None, binary: bool = False) -> bytes | str:
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise PolicyError("required command failed") from exc
    if binary:
        return completed.stdout
    return completed.stdout.decode("utf-8", "strict").strip()


def normalized_path(raw: str, allow_root: bool = True) -> str:
    if not raw or "\x00" in raw or "\\" in raw:
        fail("invalid package path")
    while raw.startswith("./"):
        raw = raw[2:]
    raw = raw.rstrip("/")
    if not raw:
        return "." if allow_root else fail("root path not allowed")
    path = PurePosixPath(raw)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        fail("non-normal package path")
    return path.as_posix()


def validate_build_reference(reference: str) -> None:
    if reference != EXPECTED_BUILD_IMAGE:
        fail("unapproved or mutable build image")
    if not re.fullmatch(r"[a-z0-9._/-]+@sha256:[0-9a-f]{64}", reference):
        fail("invalid immutable build image")


def validate_hex(value: str, length: int, field: str) -> None:
    if not re.fullmatch(rf"[0-9a-f]{{{length}}}", value):
        fail(f"invalid {field}")


def validate_provenance_document(document: dict[str, Any]) -> None:
    if set(document) != {"schema", "source", "build", "package"}:
        fail("incomplete provenance")
    if document["schema"] != PROVENANCE_SCHEMA:
        fail("invalid provenance schema")
    source = document["source"]
    if set(source) != {
        "base_commit", "base_tree", "candidate_commit", "candidate_tree",
        "candidate_source_sha256", "source_export_clean",
    }:
        fail("incomplete provenance source identity")
    if source["base_commit"] != EXPECTED_BASE_COMMIT or source["base_tree"] != EXPECTED_BASE_TREE:
        fail("provenance source base mismatch")
    validate_hex(source["candidate_commit"], 40, "provenance candidate commit")
    validate_hex(source["candidate_tree"], 40, "provenance candidate tree")
    validate_hex(source["candidate_source_sha256"], 64, "provenance candidate source hash")
    if source["source_export_clean"] is not True:
        fail("provenance source is not clean")
    build = document["build"]
    if set(build) != {"image_digest", "source_date_epoch", "lockfile_sha256", "allowlist_sha256"}:
        fail("incomplete provenance build identity")
    validate_build_reference(build["image_digest"])
    if not isinstance(build["source_date_epoch"], int) or build["source_date_epoch"] < 0:
        fail("invalid provenance source epoch")
    validate_hex(build["lockfile_sha256"], 64, "provenance lockfile hash")
    validate_hex(build["allowlist_sha256"], 64, "provenance allowlist hash")
    package = document["package"]
    if set(package) != {"name", "version", "architecture", "payload_manifest_sha256_excluding_provenance", "final_deb_sha256_evidence"}:
        fail("incomplete provenance package identity")
    if package["name"] != "casanode-api" or package["architecture"] != "all" or not package["version"]:
        fail("invalid provenance package identity")
    validate_hex(package["payload_manifest_sha256_excluding_provenance"], 64, "provenance payload hash")
    if package["final_deb_sha256_evidence"] != "external-build-result-json":
        fail("invalid final package hash evidence boundary")


def load_allowlist(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PolicyError("invalid allowlist") from exc
    if set(document) != {"schema", "package", "members"} or document["schema"] != SCHEMA:
        fail("unknown allowlist structure")
    if document["package"] != {"name": "casanode-api", "architecture": "all"}:
        fail("unexpected allowlist package identity")
    if not isinstance(document["members"], list) or not document["members"]:
        fail("empty allowlist")
    seen: set[tuple[str, str]] = set()
    for member in document["members"]:
        if set(member) != {"scope", "path", "type", "owner", "group", "mode", "source"}:
            fail("unknown allowlist member field")
        scope = member["scope"]
        path_value = normalized_path(member["path"])
        if scope not in {"control", "data"} or member["path"] != path_value:
            fail("invalid allowlist member identity")
        key = (scope, path_value)
        if key in seen:
            fail("duplicate allowlist member")
        seen.add(key)
        if member["type"] not in {"directory", "file"}:
            fail("special allowlist member forbidden")
        if member["owner"] != "root" or member["group"] != "root":
            fail("non-root package ownership forbidden")
        if not re.fullmatch(r"0[0-7]{3}", member["mode"]):
            fail("invalid allowlist mode")
        if member["type"] == "directory" and member["source"] is not None:
            fail("directory source must be null")
        if member["type"] == "file" and not isinstance(member["source"], str):
            fail("file source required")
    for scope in ("control", "data"):
        if (scope, ".") not in seen:
            fail("scope root missing from allowlist")
    return document


def member_map(document: dict[str, Any], scope: str | None = None) -> dict[tuple[str, str], dict[str, Any]]:
    return {
        (member["scope"], member["path"]): member
        for member in document["members"]
        if scope is None or member["scope"] == scope
    }


def path_is_forbidden(path: str) -> bool:
    lowered = PurePosixPath(path).name.lower()
    if any(lowered.endswith(suffix) for suffix in FORBIDDEN_SUFFIXES):
        return True
    parts = {part.lower() for part in PurePosixPath(path).parts}
    return bool(parts & RETIRED_COMPONENTS)


def parse_der_length(data: bytes, offset: int) -> tuple[int, int] | None:
    if offset >= len(data):
        return None
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    count = first & 0x7F
    if count == 0 or count > 4 or offset + 1 + count > len(data):
        return None
    return int.from_bytes(data[offset + 1:offset + 1 + count], "big"), offset + 1 + count


def der_children(data: bytes) -> list[int] | None:
    if len(data) < 4 or data[0] != 0x30:
        return None
    parsed = parse_der_length(data, 1)
    if parsed is None:
        return None
    length, offset = parsed
    end = offset + length
    if end > len(data):
        return None
    tags: list[int] = []
    while offset < end:
        tag = data[offset]
        parsed = parse_der_length(data, offset + 1)
        if parsed is None:
            return None
        child_length, content = parsed
        child_end = content + child_length
        if child_end > end:
            return None
        tags.append(tag)
        offset = child_end
    return tags if offset == end else None


def looks_like_der_private_key(data: bytes) -> bool:
    tags = der_children(data)
    if not tags:
        return False
    # PKCS#1 RSA: version plus at least eight key integers.
    if len(tags) >= 9 and all(tag == 0x02 for tag in tags[:9]):
        return True
    # PKCS#8: version, AlgorithmIdentifier sequence, privateKey octet string.
    if len(tags) >= 3 and tags[:3] == [0x02, 0x30, 0x04]:
        return True
    # SEC1 EC: version, privateKey octet string, followed by context fields.
    if len(tags) >= 3 and tags[0:2] == [0x02, 0x04] and any(tag in (0xA0, 0xA1) for tag in tags[2:]):
        return True
    return False


def forbidden_content_class(data: bytes) -> str | None:
    if any(marker in data for marker in FORBIDDEN_PEM_MARKERS):
        return "pem-or-openssh-key-or-certificate"
    if looks_like_der_private_key(data):
        return "der-private-key"
    return None


def scan_member(path: str, data: bytes) -> None:
    if path_is_forbidden(path):
        fail(f"forbidden member path: {path}")
    content_class = forbidden_content_class(data)
    if content_class:
        fail(f"forbidden member content class: {content_class}")


def validate_shared_ca_references(root: Path) -> None:
    for relative in (Path("app/src"), Path("app/dist")):
        scan_root = root / relative
        if not scan_root.exists():
            continue
        for path in sorted(scan_root.rglob("*")):
            if not path.is_file():
                continue
            data = path.read_bytes()
            if any(term in data for term in FORBIDDEN_SHARED_CA_TERMS):
                fail("forbidden shared-CA source or compiled reference")


def git_text(repo: Path, *args: str) -> str:
    return str(run_checked(["git", *args], cwd=repo))


def validate_release_source(repo: Path, expected_commit: str | None, expected_tree: str | None) -> tuple[str, str]:
    if expected_commit is None or expected_tree is None:
        fail("exact expected candidate commit and tree are required")
    validate_hex(expected_commit, 40, "expected candidate commit")
    validate_hex(expected_tree, 40, "expected candidate tree")

    actual_commit = git_text(repo, "rev-parse", "--verify", "HEAD^{commit}")
    actual_tree = git_text(repo, "rev-parse", "--verify", "HEAD^{tree}")
    if actual_commit != expected_commit:
        fail("candidate commit mismatch")
    if actual_tree != expected_tree:
        fail("candidate tree mismatch")

    status = run_checked(
        ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
        cwd=repo,
        binary=True,
    )
    assert isinstance(status, bytes)
    if status:
        fail("release source worktree is dirty")

    base_commit = git_text(repo, "rev-parse", "--verify", f"{EXPECTED_BASE_COMMIT}^{{commit}}")
    base_tree = git_text(repo, "rev-parse", "--verify", f"{EXPECTED_BASE_COMMIT}^{{tree}}")
    if base_commit != EXPECTED_BASE_COMMIT or base_tree != EXPECTED_BASE_TREE:
        fail("historical upstream base mismatch")
    run_checked(["git", "merge-base", "--is-ancestor", EXPECTED_BASE_COMMIT, actual_commit], cwd=repo)
    return actual_commit, actual_tree


def committed_blob_entries(repo: Path, commit: str) -> list[tuple[str, str, str]]:
    raw = run_checked(
        ["git", "ls-tree", "-r", "-z", "--full-tree", commit],
        cwd=repo,
        binary=True,
    )
    assert isinstance(raw, bytes)
    entries: list[tuple[str, str, str]] = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            header, raw_path = record.split(b"\t", 1)
            mode, object_type, object_id = header.decode("ascii").split(" ")
            path = normalized_path(raw_path.decode("utf-8", "strict"), allow_root=False)
        except (ValueError, UnicodeError) as exc:
            raise PolicyError("invalid committed source entry") from exc
        if mode not in {"100644", "100755"} or object_type != "blob":
            fail("committed source permits regular files only")
        validate_hex(object_id, 40, "committed blob object")
        entries.append((path, mode, object_id))
    if not entries:
        fail("committed source tree is empty")
    return entries


def export_source(
    repo: Path,
    destination: Path,
    identity_output: Path,
    expected_commit: str | None,
    expected_tree: str | None,
) -> None:
    actual_commit, actual_tree = validate_release_source(repo, expected_commit, expected_tree)
    if destination.exists():
        fail("source export destination already exists")
    destination.mkdir(mode=0o700, parents=True)
    records: list[dict[str, Any]] = []
    for relative, git_mode, object_id in committed_blob_entries(repo, actual_commit):
        target = destination / relative
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        data = run_checked(["git", "cat-file", "blob", object_id], cwd=repo, binary=True)
        assert isinstance(data, bytes)
        target.write_bytes(data)
        mode = 0o755 if git_mode == "100755" else 0o644
        os.chmod(target, mode)
        records.append({"path": relative, "mode": f"{mode:04o}", "sha256": sha256_file(target)})
    export_digest = sha256_bytes(canonical_json(records))
    identity = {
        "schema": "indigitus.casanode-api.source-export.v1",
        "base_commit": EXPECTED_BASE_COMMIT,
        "base_tree": EXPECTED_BASE_TREE,
        "candidate_commit": actual_commit,
        "candidate_tree": actual_tree,
        "candidate_source_sha256": export_digest,
        "source_export_clean": True,
        "file_count": len(records),
    }
    write_json(identity_output, identity)


def expected_compiled_paths(document: dict[str, Any]) -> set[str]:
    result = set()
    for member in document["members"]:
        source = member["source"]
        if isinstance(source, str) and source.startswith("app/dist/"):
            result.add(source.removeprefix("app/dist/"))
    return result


def validate_compiled(root: Path, document: dict[str, Any]) -> None:
    dist = root / "app/dist"
    if dist.is_symlink() or not dist.is_dir():
        fail("compiled output directory invalid")
    actual = set()
    for path in dist.rglob("*"):
        if path.is_symlink() or (not path.is_file() and not path.is_dir()):
            fail("special compiled output forbidden")
        if path.is_file():
            actual.add(path.relative_to(dist).as_posix())
    expected = expected_compiled_paths(document)
    if actual != expected:
        fail("compiled output does not match allowlist")
    validate_shared_ca_references(root)


def render_control(source: Path, version: str) -> bytes:
    text = source.read_text("utf-8")
    rendered, count = re.subn(r"(?m)^Version: .*?$", f"Version: {version}", text)
    if count != 1:
        fail("control version field invalid")
    return rendered.encode("utf-8")


def render_config(source: Path, version: str) -> bytes:
    text = source.read_text("utf-8")
    rendered, count = re.subn(r"(?m)^CASANODE_VERSION=.*?$", f"CASANODE_VERSION={version}", text)
    if count != 1:
        fail("configuration version field invalid")
    return rendered.encode("utf-8")


def render_runtime_package(source: Path) -> bytes:
    try:
        document = json.loads(source.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError("invalid application package manifest") from exc
    document["scripts"] = {"start": "node ./main.js"}
    return (json.dumps(document, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("utf-8")


def target_for_member(stage: Path, member: dict[str, Any]) -> Path:
    base = stage / "DEBIAN" if member["scope"] == "control" else stage
    return base if member["path"] == "." else base / member["path"]


def collect_stage_records(stage: Path, document: dict[str, Any], exclude: set[tuple[str, str]] | None = None) -> list[dict[str, Any]]:
    excluded = exclude or set()
    records: list[dict[str, Any]] = []
    for member in sorted(document["members"], key=lambda item: (item["scope"], item["path"].encode("utf-8"))):
        key = (member["scope"], member["path"])
        if key in excluded:
            continue
        target = target_for_member(stage, member)
        record = {
            "scope": member["scope"],
            "path": member["path"],
            "type": member["type"],
            "mode": member["mode"],
            "uid": 0,
            "gid": 0,
        }
        if member["type"] == "file":
            record["size_bytes"] = target.stat().st_size
            record["content_sha256"] = sha256_file(target)
        records.append(record)
    return records


def validate_stage(stage: Path, document: dict[str, Any]) -> None:
    expected = member_map(document)
    actual: set[tuple[str, str]] = set()
    for scope, root in (("control", stage / "DEBIAN"), ("data", stage)):
        if root.is_symlink() or not root.is_dir():
            fail("package scope root invalid")
        actual.add((scope, "."))
        for path in root.rglob("*"):
            if scope == "data" and (path == stage / "DEBIAN" or stage / "DEBIAN" in path.parents):
                continue
            relative = path.relative_to(root).as_posix()
            if path.is_symlink() or (not path.is_dir() and not path.is_file()):
                fail("special package member forbidden")
            actual.add((scope, relative))
    if actual != set(expected):
        fail("staged package does not match allowlist")
    for key, member in expected.items():
        target = target_for_member(stage, member)
        mode = stat.S_IMODE(target.lstat().st_mode)
        expected_mode = int(member["mode"], 8)
        if mode != expected_mode:
            fail("staged package mode mismatch")
        if target.lstat().st_uid != 0 or target.lstat().st_gid != 0:
            fail("staged package ownership mismatch")
        if member["type"] == "file":
            scan_member(member["path"], target.read_bytes())


def stage_package(
    root: Path,
    stage: Path,
    allowlist_path: Path,
    version: str,
    source_identity_path: Path,
    build_image: str,
    source_date_epoch: int,
    expected_candidate_commit: str,
    expected_candidate_tree: str,
) -> None:
    validate_build_reference(build_image)
    validate_hex(expected_candidate_commit, 40, "expected candidate commit")
    validate_hex(expected_candidate_tree, 40, "expected candidate tree")
    document = load_allowlist(allowlist_path)
    validate_compiled(root, document)
    if stage.exists():
        fail("package staging path already exists")
    stage.mkdir(mode=0o755, parents=True)
    identity = json.loads(source_identity_path.read_text("utf-8"))
    if identity.get("schema") != "indigitus.casanode-api.source-export.v1" or not identity.get("source_export_clean"):
        fail("invalid source export identity")
    if identity.get("base_commit") != EXPECTED_BASE_COMMIT or identity.get("base_tree") != EXPECTED_BASE_TREE:
        fail("source export base mismatch")
    if identity.get("candidate_commit") != expected_candidate_commit:
        fail("source export candidate commit mismatch")
    if identity.get("candidate_tree") != expected_candidate_tree:
        fail("source export candidate tree mismatch")
    validate_hex(str(identity.get("candidate_source_sha256", "")), 64, "candidate source hash")
    lockfile_hash = sha256_file(root / "app/package-lock.json")
    allowlist_hash = sha256_file(allowlist_path)

    provenance_member: dict[str, Any] | None = None
    for member in document["members"]:
        target = target_for_member(stage, member)
        if member["type"] == "directory":
            target.mkdir(mode=int(member["mode"], 8), parents=True, exist_ok=True)
            continue
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        source_name = member["source"]
        if source_name == "generated:control":
            data = render_control(root / "package/deb/DEBIAN/control", version)
        elif source_name == "generated:config":
            data = render_config(root / "package/deb/etc/casanode.conf", version)
        elif source_name == "generated:runtime-package-json":
            data = render_runtime_package(root / "app/package.json")
        elif source_name == "generated:provenance":
            provenance_member = member
            continue
        else:
            source = root / source_name
            if source.is_symlink() or not source.is_file():
                fail("allowlisted source missing or invalid")
            data = source.read_bytes()
        target.write_bytes(data)
        os.chmod(target, int(member["mode"], 8))

    if provenance_member is None:
        fail("provenance member missing")
    excluded = {(provenance_member["scope"], provenance_member["path"])}
    payload_records = collect_stage_records(stage, document, excluded)
    payload_manifest_hash = sha256_bytes(canonical_json(payload_records))
    provenance = {
        "schema": PROVENANCE_SCHEMA,
        "source": {
            "base_commit": EXPECTED_BASE_COMMIT,
            "base_tree": EXPECTED_BASE_TREE,
            "candidate_commit": expected_candidate_commit,
            "candidate_tree": expected_candidate_tree,
            "candidate_source_sha256": identity["candidate_source_sha256"],
            "source_export_clean": True,
        },
        "build": {
            "image_digest": build_image,
            "source_date_epoch": source_date_epoch,
            "lockfile_sha256": lockfile_hash,
            "allowlist_sha256": allowlist_hash,
        },
        "package": {
            "name": "casanode-api",
            "version": version,
            "architecture": "all",
            "payload_manifest_sha256_excluding_provenance": payload_manifest_hash,
            "final_deb_sha256_evidence": "external-build-result-json",
        },
    }
    validate_provenance_document(provenance)
    provenance_target = target_for_member(stage, provenance_member)
    write_json(provenance_target, provenance)
    os.chmod(provenance_target, int(provenance_member["mode"], 8))

    # Normalize leaf mtimes first and directory mtimes last. Creating or touching
    # a child changes its parent's mtime, so this ordering is required for the
    # package archive to inherit the exact reproducible epoch at every level.
    for member in sorted(
        document["members"],
        key=lambda item: len(PurePosixPath(item["path"]).parts),
        reverse=True,
    ):
        target = target_for_member(stage, member)
        os.chmod(target, int(member["mode"], 8))
        os.chown(target, 0, 0)
        os.utime(target, (source_date_epoch, source_date_epoch), follow_symlinks=False)
    validate_stage(stage, document)


def tar_member_type(member: tarfile.TarInfo) -> str:
    if member.isdir():
        return "directory"
    if member.isfile():
        return "file"
    if member.issym():
        return "symlink"
    return "special"


def inspect_tar(raw: bytes, scope: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    try:
        archive = tarfile.open(fileobj=io.BytesIO(raw), mode="r:*")
    except tarfile.TarError as exc:
        raise PolicyError("invalid Debian tar member") from exc
    with archive:
        for member in archive:
            path = normalized_path(member.name)
            if path in seen:
                fail("duplicate Debian archive member")
            seen.add(path)
            kind = tar_member_type(member)
            if kind not in {"directory", "file"}:
                fail("device, symlink, or special Debian member forbidden")
            if member.uid != 0 or member.gid != 0 or member.uname != "root" or member.gname != "root":
                fail("Debian archive ownership mismatch")
            record: dict[str, Any] = {
                "scope": scope,
                "path": path,
                "type": kind,
                "mode": f"{member.mode & 0o7777:04o}",
                "uid": member.uid,
                "gid": member.gid,
                "mtime_epoch": member.mtime,
            }
            if kind == "file":
                handle = archive.extractfile(member)
                if handle is None:
                    fail("unreadable Debian archive member")
                data = handle.read()
                scan_member(path, data)
                record["size_bytes"] = len(data)
                record["content_sha256"] = sha256_bytes(data)
            records.append(record)
    return records


def validate_deb(deb: Path, allowlist_path: Path, source_date_epoch: int) -> dict[str, Any]:
    document = load_allowlist(allowlist_path)
    expected = member_map(document)
    control_raw = run_checked(["dpkg-deb", "--ctrl-tarfile", str(deb)], binary=True)
    data_raw = run_checked(["dpkg-deb", "--fsys-tarfile", str(deb)], binary=True)
    assert isinstance(control_raw, bytes) and isinstance(data_raw, bytes)
    records = inspect_tar(control_raw, "control") + inspect_tar(data_raw, "data")
    actual = {(record["scope"], record["path"]): record for record in records}
    if len(actual) != len(records):
        fail("duplicate normalized Debian archive member")
    if set(actual) != set(expected):
        fail("Debian package members do not match allowlist")
    for key, member in expected.items():
        record = actual[key]
        if record["type"] != member["type"] or record["mode"] != member["mode"]:
            fail("Debian package type or mode mismatch")
        if record["uid"] != 0 or record["gid"] != 0:
            fail("Debian package numeric owner mismatch")
        if record["mtime_epoch"] != source_date_epoch:
            fail("Debian package timestamp mismatch")
    records.sort(key=lambda item: (item["scope"], item["path"].encode("utf-8")))
    manifest = {
        "schema": "indigitus.casanode-api.package-member-manifest.v1",
        "source_date_epoch": source_date_epoch,
        "member_count": len(records),
        "members": records,
    }
    manifest["manifest_sha256"] = sha256_bytes(canonical_json(manifest))
    return manifest


def build_result(deb: Path, manifest_path: Path) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text("utf-8"))
    return {
        "schema": RESULT_SCHEMA,
        "package": {
            "filename": deb.name,
            "sha256": sha256_file(deb),
            "size_bytes": deb.stat().st_size,
            "member_count": manifest["member_count"],
            "normalized_manifest_sha256": manifest["manifest_sha256"],
        },
    }


def compare_builds(deb_a: Path, manifest_a: Path, deb_b: Path, manifest_b: Path) -> dict[str, Any]:
    hash_a, hash_b = sha256_file(deb_a), sha256_file(deb_b)
    manifest_hash_a, manifest_hash_b = sha256_file(manifest_a), sha256_file(manifest_b)
    result = {
        "schema": "indigitus.casanode-api.package-comparison.v1",
        "byte_identical": hash_a == hash_b,
        "normalized_manifests_identical": manifest_hash_a == manifest_hash_b,
        "build_a": {"package_sha256": hash_a, "manifest_sha256": manifest_hash_a},
        "build_b": {"package_sha256": hash_b, "manifest_sha256": manifest_hash_b},
        "release_blocking": hash_a != hash_b or manifest_hash_a != manifest_hash_b,
        "contains_raw_content": False,
    }
    return result


def cli() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    export = subparsers.add_parser("export-source")
    export.add_argument("--repository", type=Path, required=True)
    export.add_argument("--destination", type=Path, required=True)
    export.add_argument("--identity-output", type=Path, required=True)
    export.add_argument("--expected-commit", required=True)
    export.add_argument("--expected-tree", required=True)

    compiled = subparsers.add_parser("validate-compiled")
    compiled.add_argument("--root", type=Path, required=True)
    compiled.add_argument("--allowlist", type=Path, required=True)

    stage = subparsers.add_parser("stage")
    stage.add_argument("--root", type=Path, required=True)
    stage.add_argument("--stage", type=Path, required=True)
    stage.add_argument("--allowlist", type=Path, required=True)
    stage.add_argument("--version", required=True)
    stage.add_argument("--source-identity", type=Path, required=True)
    stage.add_argument("--build-image", required=True)
    stage.add_argument("--source-date-epoch", type=int, required=True)
    stage.add_argument("--expected-candidate-commit", required=True)
    stage.add_argument("--expected-candidate-tree", required=True)

    validate = subparsers.add_parser("validate-deb")
    validate.add_argument("--deb", type=Path, required=True)
    validate.add_argument("--allowlist", type=Path, required=True)
    validate.add_argument("--source-date-epoch", type=int, required=True)
    validate.add_argument("--output", type=Path, required=True)

    result_parser = subparsers.add_parser("build-result")
    result_parser.add_argument("--deb", type=Path, required=True)
    result_parser.add_argument("--manifest", type=Path, required=True)
    result_parser.add_argument("--output", type=Path, required=True)

    compare = subparsers.add_parser("compare")
    compare.add_argument("--deb-a", type=Path, required=True)
    compare.add_argument("--manifest-a", type=Path, required=True)
    compare.add_argument("--deb-b", type=Path, required=True)
    compare.add_argument("--manifest-b", type=Path, required=True)
    compare.add_argument("--output", type=Path, required=True)

    args = parser.parse_args()
    try:
        if args.command == "export-source":
            export_source(
                args.repository.resolve(), args.destination, args.identity_output,
                args.expected_commit, args.expected_tree,
            )
        elif args.command == "validate-compiled":
            validate_compiled(args.root, load_allowlist(args.allowlist))
        elif args.command == "stage":
            stage_package(
                args.root, args.stage, args.allowlist, args.version,
                args.source_identity, args.build_image, args.source_date_epoch,
                args.expected_candidate_commit, args.expected_candidate_tree,
            )
        elif args.command == "validate-deb":
            write_json(args.output, validate_deb(args.deb, args.allowlist, args.source_date_epoch))
        elif args.command == "build-result":
            write_json(args.output, build_result(args.deb, args.manifest))
        elif args.command == "compare":
            result = compare_builds(args.deb_a, args.manifest_a, args.deb_b, args.manifest_b)
            write_json(args.output, result)
            if result["release_blocking"]:
                return 1
    except PolicyError as exc:
        print(f"P1 policy failure: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
