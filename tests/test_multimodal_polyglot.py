"""
Polyglot upload tests.

A file can be a structurally valid image by magic bytes and still carry
executable markup in its body — the GIFAR/polyglot vector. `validate_bytes`
checked magic bytes, type spoofing, filenames and size, but never looked at
the image body, so b"GIF89a;<script>alert(1)</script>" passed every check.

The false-positive test below matters as much as the detection tests. The
first version of this check included b"<%" as a marker. Two bytes appear with
near-certainty somewhere in a multi-megabyte file, so ordinary photographs
were rejected. Markers must be long enough not to occur by chance in
compressed binary.
"""

import os

import pytest

from sovereign_shield.multimodal_filter import (
    MultiModalFilter,
    _POLYGLOT_MARKERS,
)


@pytest.fixture
def mmf():
    return MultiModalFilter()


JPEG = b"\xff\xd8\xff\xe0"
PNG = b"\x89PNG\r\n\x1a\n"
GIF = b"GIF89a"


class TestPolyglotBlocked:

    @pytest.mark.parametrize("label,data", [
        ("gif_script", GIF + b";<script>alert(1)</script>"),
        ("gif_script_uppercase", GIF + b";<SCRIPT>alert(1)</SCRIPT>"),
        ("jpeg_php", JPEG + b"\x00" * 80 + b"<?php system($_GET[0]); ?>"),
        ("png_iframe", PNG + b"\x00" * 60 + b"<iframe src=evil>"),
        ("jpeg_javascript_uri", JPEG + b"javascript:alert(1)" + b"\x00" * 40),
        ("jpeg_html", JPEG + b"<html><body>x"),
        ("jpeg_doctype", JPEG + b"<!DOCTYPE HTML><body>x"),
    ])
    def test_blocked(self, mmf, label, data):
        result = mmf.validate_bytes(data, filename="a.img")
        assert result["allowed"] is False, label
        assert "polyglot" in result["reason"].lower(), label


class TestNoFalsePositives:

    def test_random_image_bodies(self, mmf):
        """Random binary must not trip the detector.

        ~13 MB across a range of sizes. With a 2-byte marker this failed
        immediately; every marker is now >= 5 bytes.
        """
        for i in range(1, 26):
            body = JPEG + os.urandom(i * 64 * 1024)
            result = mmf.validate_bytes(body, filename=f"p{i}.jpg")
            assert result["allowed"] is True, (
                f"{i * 64}KB random JPEG body was rejected: {result['reason']}"
            )

    def test_markers_are_long_enough(self):
        """Guards the invariant directly, not just its consequences."""
        for marker in _POLYGLOT_MARKERS:
            assert len(marker) >= 5, f"{marker!r} is too short to be evidence"

    def test_genuine_jpeg_with_exif(self, mmf):
        data = JPEG[:2] + b"\xff\xe1" + b"Exif\x00\x00" + os.urandom(200)
        assert mmf.validate_bytes(data, filename="a.jpg")["allowed"] is True


class TestOptOut:

    def test_detection_can_be_disabled(self):
        mmf = MultiModalFilter(detect_polyglots=False)
        result = mmf.validate_bytes(GIF + b";<script>x</script>", filename="a.gif")
        assert result["allowed"] is True


class TestExistingChecksUnaffected:

    @pytest.mark.parametrize("label,data,kwargs", [
        ("pe_as_jpg", b"MZ" + b"\x00" * 100,
         {"filename": "photo.jpg", "declared_type": "image/jpeg"}),
        ("elf", b"\x7fELF" + b"\x00" * 100, {"filename": "a.png"}),
        ("traversal", b"hello", {"filename": "../../../etc/passwd"}),
        ("null_byte", b"hello", {"filename": "photo.jpg\x00.exe"}),
        ("empty", b"", {"filename": "a.txt"}),
    ])
    def test_still_blocked(self, mmf, label, data, kwargs):
        assert mmf.validate_bytes(data, **kwargs)["allowed"] is False, label

    def test_type_spoof_still_blocked(self, mmf):
        result = mmf.validate_bytes(PNG + b"\x00" * 80, filename="a.jpg",
                                    declared_type="image/jpeg")
        assert result["allowed"] is False
        assert "mismatch" in result["reason"].lower()
