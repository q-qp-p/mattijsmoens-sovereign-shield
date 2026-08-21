"""
MultiModalFilter — Binary File Validation Engine
==================================================
Validates file uploads by checking magic bytes, MIME type consistency,
file size limits, filename safety, and metadata stripping flags.

Blocks:
    - Type spoofing (PNG bytes declared as JPEG)
    - Executable payloads (MZ, ELF, Mach-O headers)
    - Path traversal in filenames (../, ..\\\\)
    - Null byte injection in filenames
    - Double extensions with dangerous types (.exe.jpg)
    - Oversized files
    - Disallowed MIME types (archives, executables)

Also provides text extraction validation to catch prompt injection
smuggled through OCR or document parsing.

Zero external dependencies. Pure Python stdlib.
"""

import logging
import re
import os

logger = logging.getLogger("sovereign_shield.multimodal_filter")

# ===================================================================
# MAGIC BYTE SIGNATURES
# ===================================================================

_MAGIC_SIGNATURES = {
    b"\xff\xd8\xff": "image/jpeg",
    b"\x89PNG\r\n\x1a\n": "image/png",
    b"GIF87a": "image/gif",
    b"GIF89a": "image/gif",
    b"RIFF": "image/webp",       # WebP (RIFF container)
    b"BM": "image/bmp",
    b"%PDF": "application/pdf",
    b"PK\x03\x04": "application/zip",
    b"MZ": "application/x-executable",
    b"\x7fELF": "application/x-executable",
    b"\xfe\xed\xfa": "application/x-executable",  # Mach-O
    b"\xcf\xfa\xed\xfe": "application/x-executable",  # Mach-O 64
}

# Executable markup that must never appear inside an image payload.
# Matched against a lowercased copy of the data, since HTML tag names are
# case-insensitive.
#
# Every marker must be at least 5 bytes. Image payloads are compressed binary,
# so a SHORT marker is not evidence of anything: b"<%" is two bytes, which
# appears with near-certainty somewhere in a multi-megabyte file by chance
# alone, and flagged ordinary photographs. b"<svg" (4 bytes) is borderline for
# the same reason and buys nothing here, since image/svg+xml is not a
# recognised magic-byte type in the first place.
_POLYGLOT_MARKERS = (
    b"<script",
    b"<?php",
    b"<!doctype html",
    b"<html",
    b"<iframe",
    b"javascript:",
)
assert all(len(m) >= 5 for m in _POLYGLOT_MARKERS), (
    "polyglot markers must be long enough not to occur by chance in binary data"
)

# MIME types allowed by default
_DEFAULT_ALLOWED_TYPES = {
    "image/jpeg", "image/png", "image/gif", "image/webp", "image/bmp",
    "application/pdf",
}

# Dangerous file extensions (blocked in double-extension check)
_DANGEROUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".com", ".msi", ".scr", ".pif",
    ".sh", ".bash", ".ps1", ".vbs", ".js", ".ws", ".wsf",
    ".dll", ".sys", ".drv", ".cpl",
    ".py", ".rb", ".pl", ".php",
}

# JPEG APP1 marker indicates EXIF data
_JPEG_EXIF_MARKER = b"\xff\xe1"

# Prompt injection keywords for extracted text validation
_TEXT_INJECTION_SIGNALS = [
    "IGNORE PREVIOUS", "SYSTEM PROMPT", "IGNORE ALL INSTRUCTIONS",
    "DISREGARD ALL", "FORGET ALL", "NEW SYSTEM PROMPT",
    "OVERRIDE SYSTEM", "JAILBREAK", "DEVELOPER MODE",
    "ADMIN ACCESS", "DAN MODE", "DROP DATABASE",
]

# Import InputFilter's signals for more comprehensive text checking
try:
    from .input_filter import InputFilter as _InputFilter
    _HAS_INPUT_FILTER = True
except ImportError:
    _HAS_INPUT_FILTER = False


class MultiModalFilter:
    """
    Binary file validation and extracted text sanitization.

    Validates file uploads through magic byte analysis, MIME type
    consistency checking, filename safety, and size limits.

    Usage:
        mmf = MultiModalFilter()
        result = mmf.validate_bytes(file_data, filename="photo.jpg",
                                     declared_type="image/jpeg")
        if not result["allowed"]:
            print(f"Blocked: {result['reason']}")
    """

    def __init__(
        self,
        allowed_types=None,
        max_file_size_mb=25,
        max_filename_length=255,
        detect_polyglots=True,
    ):
        """
        Args:
            allowed_types: Set of allowed MIME types. Uses defaults if None.
            max_file_size_mb: Maximum file size in megabytes.
            max_filename_length: Maximum filename length in characters.
            detect_polyglots: Reject files that are a structurally valid image
                by magic bytes but carry executable markup in their body (the
                GIFAR/polyglot vector). Enabled by default.
        """
        self.allowed_types = allowed_types or _DEFAULT_ALLOWED_TYPES
        self.max_file_size_bytes = int(max_file_size_mb * 1024 * 1024)
        self.max_filename_length = max_filename_length
        self.detect_polyglots = detect_polyglots
        self._input_filter = _InputFilter() if _HAS_INPUT_FILTER else None

    def _detect_type(self, data):
        """Detect MIME type from magic bytes."""
        for magic, mime_type in _MAGIC_SIGNATURES.items():
            if data[:len(magic)] == magic:
                # Special case: WebP needs RIFF + "WEBP" at offset 8
                if magic == b"RIFF" and len(data) >= 12:
                    if data[8:12] != b"WEBP":
                        continue
                return mime_type
        return "application/octet-stream"

    @staticmethod
    def _find_polyglot_marker(data):
        """Return the first executable-markup marker found, or None.

        Only high-signal sequences are used. Image payloads are compressed
        binary, so an exact match on any of these is vanishingly unlikely to
        occur by chance even in a multi-megabyte file.
        """
        lowered = data.lower()
        for marker in _POLYGLOT_MARKERS:
            if marker in lowered:
                return marker.decode("ascii", "replace")
        return None

    def _check_exif(self, data):
        """Check if JPEG data contains EXIF metadata (APP1 marker)."""
        if len(data) >= 4 and data[:2] == b"\xff\xd8":
            # Check the marker right after SOI
            if data[2:4] == _JPEG_EXIF_MARKER:
                return True
        return False

    def validate_bytes(self, data, filename="", declared_type=None):
        """
        Validate binary file data.

        Args:
            data: Raw file bytes.
            filename: Original filename (for extension/path checks).
            declared_type: MIME type declared by the client (optional).

        Returns:
            dict with: allowed, actual_type, reason, stripped_metadata
        """
        result = {
            "allowed": False,
            "actual_type": None,
            "reason": "",
            "stripped_metadata": False,
        }

        # --- Check 1: Empty file ---
        if not data or len(data) == 0:
            result["reason"] = "Empty file rejected."
            return result

        # --- Check 2: File size ---
        if len(data) > self.max_file_size_bytes:
            size_mb = len(data) / (1024 * 1024)
            limit_mb = self.max_file_size_bytes / (1024 * 1024)
            result["reason"] = (
                f"File too large: {size_mb:.1f}MB exceeds "
                f"{limit_mb:.1f}MB limit."
            )
            return result

        # --- Check 3: Filename safety ---
        if filename:
            # Length check
            if len(filename) > self.max_filename_length:
                result["reason"] = (
                    f"Filename too long: {len(filename)} chars "
                    f"exceeds {self.max_filename_length} limit."
                )
                return result

            # Null byte injection
            if "\0" in filename:
                result["reason"] = "Null byte injection detected in filename."
                return result

            # Path traversal
            if ".." in filename or "/" in filename or "\\" in filename:
                result["reason"] = "Path traversal detected in filename."
                return result

            # Double extension with dangerous type
            parts = filename.lower().split(".")
            if len(parts) >= 3:
                for ext in parts[1:-1]:  # Check middle extensions
                    if f".{ext}" in _DANGEROUS_EXTENSIONS:
                        result["reason"] = (
                            f"Dangerous extension '.{ext}' detected "
                            f"in multi-extension filename."
                        )
                        return result

        # --- Check 4: Magic byte detection ---
        actual_type = self._detect_type(data)
        result["actual_type"] = actual_type

        # --- Check 5: Executable payload ---
        if actual_type == "application/x-executable":
            result["reason"] = "Executable payload detected (blocked)."
            return result

        # --- Check 6: Allowed type check ---
        if actual_type not in self.allowed_types:
            result["reason"] = (
                f"File type '{actual_type}' is not in the allowed list."
            )
            return result

        # --- Check 7: Type spoofing ---
        if declared_type and declared_type != actual_type:
            result["reason"] = (
                f"Type mismatch: declared '{declared_type}' but "
                f"actual magic bytes indicate '{actual_type}'."
            )
            return result

        # --- Check 8: Polyglot payload ---
        # A file can be a structurally valid image by magic bytes and still
        # carry executable markup in its body - the GIFAR/polyglot vector,
        # e.g. b"GIF89a;<script>...</script>", which passes every check above.
        # Compressed image data essentially never contains these byte
        # sequences by chance, so a hit is strong evidence of a smuggled
        # payload rather than a false positive.
        if self.detect_polyglots and actual_type.startswith("image/"):
            marker = self._find_polyglot_marker(data)
            if marker:
                result["reason"] = (
                    f"Polyglot payload detected: valid {actual_type} carrying "
                    f"embedded markup ({marker!r})."
                )
                return result

        # --- Check 9: EXIF metadata detection ---
        if actual_type == "image/jpeg":
            has_exif = self._check_exif(data)
            result["stripped_metadata"] = has_exif

        # All checks passed
        result["allowed"] = True
        result["reason"] = "File validated successfully."
        return result

    def validate_extracted_text(self, text, source="OCR"):
        """
        Validate text extracted from a file (OCR, PDF parsing, etc.)
        for prompt injection attempts.

        Args:
            text: Extracted text content.
            source: Where the text came from (for logging).

        Returns:
            dict with: allowed, reason, clean_text
        """
        if not text or not text.strip():
            return {
                "allowed": True,
                "reason": "Empty text.",
                "clean_text": text,
            }

        # Use InputFilter if available for comprehensive checking
        if self._input_filter:
            is_safe, result, _suspicion = self._input_filter.process(text)
            if not is_safe:
                logger.warning(
                    f"[MultiModalFilter] Blocked extracted text from {source}: "
                    f"{result}"
                )
                return {
                    "allowed": False,
                    "reason": f"Injection detected in {source} text: {result}",
                    "clean_text": None,
                }
            return {
                "allowed": True,
                "reason": "Text validated.",
                "clean_text": result,
            }

        # Fallback: simple keyword check
        upper_text = text.upper()
        for signal in _TEXT_INJECTION_SIGNALS:
            if signal in upper_text:
                logger.warning(
                    f"[MultiModalFilter] Blocked injection in {source} text: "
                    f"{signal}"
                )
                return {
                    "allowed": False,
                    "reason": f"Injection keyword detected in {source} text.",
                    "clean_text": None,
                }

        return {
            "allowed": True,
            "reason": "Text validated.",
            "clean_text": text,
        }
