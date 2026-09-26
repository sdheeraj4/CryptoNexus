import logging
import re
import stat
import tempfile
import zipfile
import zlib
from pathlib import Path

from fastapi import HTTPException, UploadFile
from pydantic import BaseModel

from app.scanner import Finding, scan_repository
from app.config_scanner import unique_findings
from app.metadata_scanner import scan_metadata
from app.certificate_scanner import CertificateIssue, scan_certificates

logger = logging.getLogger(__name__)
MAX_UPLOAD_BYTES = 20 * 1024 * 1024
MAX_EXTRACTED_BYTES = 100 * 1024 * 1024
MAX_ENTRIES = 10_000
CHUNK_SIZE = 64 * 1024
IGNORED_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
SOURCE_EXTENSIONS = {".py", ".js", ".ts", ".java", ".go", ".c", ".cpp", ".cs"}
CONFIG_EXTENSIONS = {".json", ".yaml", ".yml", ".toml", ".conf", ".ini"}
CERT_EXTENSIONS = {".pem", ".crt", ".cer"}
DEPENDENCY_NAMES = {"requirements.txt", "pyproject.toml", "package.json", "pom.xml", "go.mod"}
RESERVED_NAMES = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"} | {
    f"{prefix}{number}" for prefix in ("COM", "LPT") for number in "123456789¹²³"
}


class Inventory(BaseModel):
    project_name: str
    total_files: int
    source_files: list[str]
    config_files: list[str]
    certificate_files: list[str]
    dependency_files: list[str]


class ScanResult(Inventory):
    crypto_findings: list[Finding]
    finding_count: int
    certificate_scan_issues: list[CertificateIssue]


def safe_parts(info: zipfile.ZipInfo) -> list[str]:
    # Interpret both separator styles consistently, including ZIPs from Windows.
    name = info.orig_filename.replace("\\", "/")
    parts = name.rstrip("/").split("/")
    if (name.startswith("/") or not parts or any(
        part in {"", ".", ".."}
        or part.endswith((".", " "))
        or any(ord(char) < 32 or char in ':<>"|?*' for char in part)
        or part.split(".")[0].upper() in RESERVED_NAMES
        for part in parts
    )):
        raise HTTPException(400, "Unsafe ZIP entry path.")
    mode = info.external_attr >> 16
    if stat.S_IFMT(mode) not in {0, stat.S_IFREG, stat.S_IFDIR}:
        raise HTTPException(400, "ZIP links and special files are not allowed.")
    if info.flag_bits & 1:
        raise HTTPException(400, "Encrypted ZIP files are not supported.")
    return parts


def extract_inventory(archive_path: Path, root: Path, project_name: str) -> Inventory:
    paths: list[str] = []
    with zipfile.ZipFile(archive_path) as archive:
        entries = archive.infolist()
        if len(entries) > MAX_ENTRIES:
            raise HTTPException(413, "ZIP contains too many entries.")
        if sum(entry.file_size for entry in entries) > MAX_EXTRACTED_BYTES:
            raise HTTPException(413, "ZIP expands beyond the 100 MiB limit.")
        extracted_bytes = 0
        seen: set[str] = set()
        for entry in entries:
            parts = safe_parts(entry)
            if any(part.lower() in IGNORED_DIRS for part in (
                parts if entry.is_dir() else parts[:-1]
            )):
                continue
            destination = root.joinpath(*parts)
            if not destination.resolve().is_relative_to(root.resolve()):
                raise HTTPException(400, "Unsafe ZIP entry path.")
            key = "/".join(parts).casefold()
            if key in seen:
                raise HTTPException(400, "Duplicate ZIP entry path.")
            seen.add(key)
            if entry.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(entry) as source, destination.open("xb") as target:
                while chunk := source.read(CHUNK_SIZE):
                    extracted_bytes += len(chunk)
                    if extracted_bytes > MAX_EXTRACTED_BYTES:
                        raise HTTPException(413, "ZIP expands beyond the 100 MiB limit.")
                    target.write(chunk)
            paths.append("/".join(parts))
    paths.sort()
    return Inventory(
        project_name=project_name,
        total_files=len(paths),
        source_files=[p for p in paths if Path(p).suffix.lower() in SOURCE_EXTENSIONS],
        config_files=[p for p in paths if Path(p).suffix.lower() in CONFIG_EXTENSIONS],
        certificate_files=[p for p in paths if Path(p).suffix.lower() in CERT_EXTENSIONS],
        dependency_files=[p for p in paths if Path(p).name.lower() in DEPENDENCY_NAMES],
    )


def process_upload(upload: UploadFile) -> ScanResult:
    try:
        filename = (upload.filename or "").replace("\\", "/").split("/")[-1]
        if not filename.lower().endswith(".zip"):
            raise HTTPException(400, "Provide a repository ZIP file.")
        project_name = re.sub(r"[^\w .-]", "_", filename[:-4])[:100].strip() or "project"
        with tempfile.TemporaryDirectory(prefix="cryptonexus-") as directory:
            workspace = Path(directory)
            archive_path = workspace / "upload.zip"
            size = 0
            with archive_path.open("wb") as target:
                while chunk := upload.file.read(CHUNK_SIZE):
                    size += len(chunk)
                    if size > MAX_UPLOAD_BYTES:
                        raise HTTPException(413, "Upload exceeds the 20 MiB limit.")
                    target.write(chunk)
            root = workspace / "repository"
            root.mkdir()
            try:
                inventory = extract_inventory(archive_path, root, project_name)
            except (zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError,
                    NotImplementedError, EOFError, ValueError, OSError, zlib.error) as exc:
                raise HTTPException(400, "Invalid or unsupported ZIP archive.") from exc
            logger.info("ZIP inventoried successfully: %d files", inventory.total_files)
            findings = scan_repository(root, inventory.source_files)
            findings.extend(scan_metadata(root, inventory.config_files, inventory.dependency_files))
            certificates, certificate_issues = scan_certificates(root, inventory.certificate_files)
            findings.extend(certificates)
            findings = unique_findings(findings)
            logger.info("Repository scan completed: %d findings", len(findings))
            return ScanResult(**inventory.model_dump(), crypto_findings=findings,
                              finding_count=len(findings), certificate_scan_issues=certificate_issues)
    finally:
        upload.file.close()
