import io
import zipfile

import pytest

from geminihunter.discovery import apk


def make_zip(path, entries):
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in entries.items():
            archive.writestr(name, content)


def test_xapk_scans_nested_apk_and_metadata(monkeypatch, tmp_path):
    monkeypatch.setattr(apk.shutil, "which", lambda name: None)
    inner = io.BytesIO()
    make_zip(inner, {"assets/config.json": '{"key":"synthetic-example"}'})
    bundle = tmp_path / "sample.xapk"
    make_zip(bundle, {"splits/base.apk": inner.getvalue(), "manifest.json": '{"package":"example.app"}'})
    sources = apk.ApkScanner().scan(str(bundle))
    assert len(sources) == 2
    assert any("synthetic-example" in source.content for source in sources)


def test_xapk_rejects_excessive_expansion(monkeypatch, tmp_path):
    monkeypatch.setattr(apk, "MAX_ARCHIVE_SIZE", 16, raising=False)
    bundle = tmp_path / "sample.xapk"
    make_zip(bundle, {"manifest.json": "x" * 32})
    with pytest.raises(ValueError, match="size"):
        apk.ApkScanner().scan(str(bundle))


def test_xapk_rejects_path_traversal(tmp_path):
    bundle = tmp_path / "sample.xapk"
    make_zip(bundle, {"../escape.json": "synthetic-example"})
    with pytest.raises(ValueError, match="path"):
        apk.ApkScanner().scan(str(bundle))


def test_corrupt_apk_is_an_actionable_error(tmp_path):
    path = tmp_path / "bad.apk"
    path.write_bytes(b"not a zip")
    with pytest.raises(ValueError, match="archive"):
        apk.ApkScanner().scan(str(path))


def test_decompiled_file_size_limit(monkeypatch, tmp_path):
    monkeypatch.setattr(apk, "MAX_FILE_SIZE", 16)
    path = tmp_path / "large.java"
    path.write_text("x" * 32)
    assert apk._read_text_safe(str(path)) == ""
