"""APK/XAPK scanner -- decompiles and extracts sources for key hunting."""

import logging
import os
import re
import shutil
import subprocess
import tempfile
import zipfile

from geminihunter.models import DiscoveredSource, SourceType

logger = logging.getLogger("geminihunter")

# File extensions to read as plain text inside APKs
TEXT_EXTENSIONS = frozenset({
    ".xml", ".json", ".properties", ".txt", ".html", ".htm",
    ".js", ".css", ".yaml", ".yml", ".toml", ".ini", ".cfg",
    ".java", ".kt", ".smali", ".gradle", ".pro", ".conf",
})

# Extract printable ASCII strings >= 39 chars (min key length) from binaries
ASCII_STRINGS_RE = re.compile(rb"[\x20-\x7e]{39,}")

# Max file size to process (skip huge native libs, media, etc.)
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


class ApkScanner:
    """Decompiles and scans APK/XAPK files for API key sources."""

    def __init__(self) -> None:
        self._jadx_path = shutil.which("jadx")

    @property
    def has_jadx(self) -> bool:
        return self._jadx_path is not None

    def scan(self, apk_path: str) -> list[DiscoveredSource]:
        """Scan an APK or XAPK file, returning DiscoveredSource objects."""
        if apk_path.lower().endswith(".xapk"):
            return self._scan_xapk(apk_path)
        return self._scan_apk(apk_path)

    # --- XAPK handling ---

    def _scan_xapk(self, xapk_path: str) -> list[DiscoveredSource]:
        """XAPK is a ZIP containing one or more APKs plus metadata."""
        sources: list[DiscoveredSource] = []
        xapk_name = os.path.basename(xapk_path)

        with tempfile.TemporaryDirectory(prefix="geminihunter_xapk_") as tmpdir:
            try:
                with zipfile.ZipFile(xapk_path, "r") as zf:
                    zf.extractall(tmpdir)
            except (zipfile.BadZipFile, Exception) as e:
                logger.warning(f"Failed to extract XAPK {xapk_name}: {e}")
                return []

            for root, _dirs, files in os.walk(tmpdir):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    if fname.lower().endswith(".apk"):
                        sources.extend(self._scan_apk(fpath))
                    elif _is_text_ext(fname):
                        content = _read_text_safe(fpath)
                        if content and len(content) > 10:
                            sources.append(DiscoveredSource(
                                url=f"xapk:{xapk_name}/{fname}",
                                source_type=SourceType.APK_FILE,
                                target_domain="apk",
                                content=content,
                            ))

        return sources

    # --- Single APK ---

    def _scan_apk(self, apk_path: str) -> list[DiscoveredSource]:
        """Scan a single APK: try jadx first, then fall back to ZIP extraction."""
        apk_name = os.path.basename(apk_path)

        if self._jadx_path:
            sources = self._scan_with_jadx(apk_path, apk_name)
            if sources:
                return sources
            logger.debug(f"jadx produced no output for {apk_name}, falling back to ZIP")

        return self._scan_with_zip(apk_path, apk_name)

    # --- jadx decompilation ---

    def _scan_with_jadx(self, apk_path: str, apk_name: str) -> list[DiscoveredSource]:
        """Decompile with jadx and scan the resulting Java/resource files."""
        sources: list[DiscoveredSource] = []

        with tempfile.TemporaryDirectory(prefix="geminihunter_jadx_") as outdir:
            try:
                subprocess.run(
                    [
                        self._jadx_path,
                        "-q",              # quiet
                        "--no-imports",    # skip import statements
                        "-d", outdir,
                        apk_path,
                    ],
                    capture_output=True,
                    timeout=180,
                )
                # jadx often returns non-zero but still produces usable output
            except subprocess.TimeoutExpired:
                logger.debug(f"jadx timed out for {apk_name}")
                return []
            except FileNotFoundError:
                logger.debug("jadx binary disappeared")
                return []

            for root, _dirs, files in os.walk(outdir):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    content = _read_text_safe(fpath)
                    if content and len(content) > 10:
                        rel_path = os.path.relpath(fpath, outdir)
                        sources.append(DiscoveredSource(
                            url=f"apk:{apk_name}/{rel_path}",
                            source_type=SourceType.APK_FILE,
                            target_domain="apk",
                            content=content,
                        ))

        return sources

    # --- ZIP fallback (no external tools) ---

    def _scan_with_zip(self, apk_path: str, apk_name: str) -> list[DiscoveredSource]:
        """Extract APK as a ZIP and scan text files + binary strings."""
        sources: list[DiscoveredSource] = []

        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                for info in zf.infolist():
                    if info.is_dir() or info.file_size == 0:
                        continue
                    if info.file_size > MAX_FILE_SIZE:
                        continue

                    fname = info.filename

                    # Text files: read directly
                    if _is_text_ext(fname) or fname.startswith("assets/"):
                        try:
                            raw = zf.read(fname)
                            content = raw.decode("utf-8", errors="ignore")
                            if content and len(content) > 10:
                                sources.append(DiscoveredSource(
                                    url=f"apk:{apk_name}/{fname}",
                                    source_type=SourceType.APK_FILE,
                                    target_domain="apk",
                                    content=content,
                                ))
                        except Exception:
                            pass

                    # DEX and resources.arsc: extract strings from binary
                    elif fname.endswith(".dex") or fname == "resources.arsc":
                        try:
                            raw = zf.read(fname)
                            content = _extract_strings(raw)
                            if content:
                                sources.append(DiscoveredSource(
                                    url=f"apk:{apk_name}/{fname}",
                                    source_type=SourceType.APK_FILE,
                                    target_domain="apk",
                                    content=content,
                                ))
                        except Exception:
                            pass

        except (zipfile.BadZipFile, Exception) as e:
            logger.warning(f"Failed to open APK as ZIP {apk_path}: {e}")

        return sources


# --- helpers ---


def _extract_strings(data: bytes) -> str:
    """Extract printable ASCII strings from binary data (like `strings`)."""
    matches = ASCII_STRINGS_RE.findall(data)
    if not matches:
        return ""
    return "\n".join(m.decode("ascii", errors="ignore") for m in matches)


def _is_text_ext(fname: str) -> bool:
    _, ext = os.path.splitext(fname.lower())
    return ext in TEXT_EXTENSIONS


def _read_text_safe(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""
