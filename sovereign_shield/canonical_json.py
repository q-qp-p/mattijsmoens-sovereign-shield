"""
CanonicalJSON - Deterministic JSON Normalization.
==================================================
Normalizes JSON data so that semantically identical data produces identical
bytes - and therefore an identical SHA-256 hash - regardless of key ordering,
whitespace, or case.

This is what makes the multi-model consensus in veto.py an actual hash
comparison rather than a string comparison. Models are asked for a structured
verdict document; normalization removes the formatting variance they are
entitled to differ on, and the hash then compares everything that is left.

Ported from sovereign-mcp (same algorithm, stdlib only) so that
sovereign-shield keeps no cross-package dependency.
"""


import json
import hashlib
import hmac
import math
import logging

logger = logging.getLogger(__name__)


def normalize(data, remove_nulls=True, preserve_case=False):
    """
    Recursively normalize data for deterministic comparison.

    Args:
        data: Any JSON-compatible Python object.
        remove_nulls: Whether to remove None/null values (default: True).
        preserve_case: If True, do NOT lowercase strings (M-10).
                       Default False for backward compatibility.

    Returns:
        Normalized copy of the data (new object, original unchanged).
    """
    if data is None:
        return None
    elif isinstance(data, bool):
        # Must check bool before int (bool is subclass of int in Python)
        return data
    elif isinstance(data, int):
        return data
    elif isinstance(data, float):
        return _normalize_number(data)
    elif isinstance(data, str):
        return _normalize_string(data, preserve_case)
    elif isinstance(data, dict):
        return _normalize_dict(data, remove_nulls, preserve_case)
    elif isinstance(data, (list, tuple)):
        return _normalize_array(data, remove_nulls, preserve_case)
    else:
        # Fallback: convert to string and normalize
        return _normalize_string(str(data), preserve_case)


def _normalize_string(s, preserve_case=False):
    """Strip whitespace and optionally lowercase."""
    s = s.strip()
    return s if preserve_case else s.lower()


def _normalize_number(n):
    """
    Normalize float to consistent format.
    Remove trailing zeros, handle -0.0, handle infinity/NaN.

    NaN and Infinity are normalized to unique sentinel strings rather
    than 0 to prevent false consensus matches. If Model A returns NaN
    and Model B returns 0, their hashes MUST differ.
    """
    if math.isnan(n):
        return "__NaN__"  # Unique sentinel — never matches 0 or any real number
    if math.isinf(n):
        if n > 0:
            return "__+Infinity__"
        else:
            return "__-Infinity__"
    if n == 0.0:
        return 0  # Remove -0.0
    # If the float is actually an integer, return int
    if n == int(n):
        return int(n)
    return n


def _normalize_dict(d, remove_nulls=True, preserve_case=False):
    """Normalize a dict: sort keys, normalize values, optionally remove nulls."""
    result = {}
    for key in sorted(d.keys()):
        value = normalize(d[key], remove_nulls, preserve_case)
        if remove_nulls and value is None:
            continue
        normalized_key = str(key).strip()
        normalized_key = normalized_key if preserve_case else normalized_key.lower()
        if normalized_key in result:
            logger.warning(
                f"[CanonicalJSON] Key collision: '{key}' normalizes to "
                f"'{normalized_key}' which already exists. Last value wins."
            )
        result[normalized_key] = value
    return result


def _normalize_array(arr, remove_nulls=True, preserve_case=False):
    """Normalize an array: normalize each element.

    Note: nulls are NOT removed from arrays (unlike dicts) because
    array position is semantically meaningful. [1, null, 3] must NOT
    collapse to [1, 3] as this would alter the structure.
    """
    result = []
    for item in arr:
        normalized = normalize(item, remove_nulls, preserve_case)
        result.append(normalized)
    return result


def canonical_dumps(data, preserve_case=False):
    """
    Produce a canonical JSON string from data.

    1. Normalize the data
    2. Serialize with sorted keys and compact separators

    Args:
        data: Any JSON-compatible Python object.
        preserve_case: If True, do not lowercase strings (M-10).

    Returns:
        Canonical JSON string (deterministic byte representation).
    """
    normalized = normalize(data, preserve_case=preserve_case)
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)


def canonical_hash(data):
    """
    Compute SHA-256 hash of the canonical JSON representation of data.

    This is the core comparison mechanism for the structured JSON consensus.
    Same data → same canonical JSON → same hash. Always.

    Args:
        data: Any JSON-compatible Python object.

    Returns:
        SHA-256 hex digest string.
    """
    canonical = canonical_dumps(data)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def hashes_match(data_a, data_b):
    """
    Check if two data structures produce the same canonical hash.

    This is the deterministic accept/reject decision in the consensus.
    EXACT MATCH = accept. ANY DIFFERENCE = decline.

    Args:
        data_a: First data structure (typically Model A output).
        data_b: Second data structure (typically Model B output).

    Returns:
        tuple: (match: bool, hash_a: str, hash_b: str)
    """
    hash_a = canonical_hash(data_a)
    hash_b = canonical_hash(data_b)
    # Constant-time comparison to prevent timing attacks
    return hmac.compare_digest(hash_a, hash_b), hash_a, hash_b
