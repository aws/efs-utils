import shutil
import subprocess
import tarfile
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_NAME = "amazon-efs-utils"

DIST_FILES = (
    "amazon-efs-mount-watchdog.conf",
    "amazon-efs-mount-watchdog.service",
    "efs-utils.conf",
    "s3files-utils.conf",
    "efs-utils.crt",
)
SOURCE_DIRECTORIES = (
    "efs_utils_common",
    "mount_efs",
    "mount_s3files",
    "watchdog",
    "proxy",
    "client-core",
    "nfs-xdr-bindings",
)
MAN_FILES = ("mount.efs.8", "mount.s3files.8")


def prepare_source_tree(tmp_path, include_lockfile):
    shutil.copy2(PACKAGE_ROOT / "Makefile", tmp_path / "Makefile")

    for filename in DIST_FILES:
        path = tmp_path / "dist" / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()

    for directory in SOURCE_DIRECTORIES:
        path = tmp_path / "src" / directory / "marker"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()

    cargo_manifest = tmp_path / "src" / "Cargo.toml"
    cargo_manifest.write_text("[workspace]\n")

    if include_lockfile:
        cargo_lockfile = tmp_path / "src" / "Cargo.lock"
        cargo_lockfile.write_text("# workspace lockfile\n")

    for filename in MAN_FILES:
        path = tmp_path / "man" / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()


def build_tarball(tmp_path):
    result = subprocess.run(
        ["make", "tarball"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr

    tarball = tmp_path / f"{PACKAGE_NAME}.tar.gz"
    with tarfile.open(tarball, "r:gz") as archive:
        return set(archive.getnames())


def test_tarball_copies_workspace_lockfile_when_present(tmp_path):
    prepare_source_tree(tmp_path, include_lockfile=True)

    archive_members = build_tarball(tmp_path)

    assert f"{PACKAGE_NAME}/src/Cargo.lock" in archive_members


def test_tarball_builds_without_workspace_lockfile(tmp_path):
    prepare_source_tree(tmp_path, include_lockfile=False)

    archive_members = build_tarball(tmp_path)

    assert f"{PACKAGE_NAME}/src/Cargo.lock" not in archive_members
