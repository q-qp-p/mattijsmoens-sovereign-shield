"""
Structured multi-model consensus tests.

These pin the property that makes the "cryptographic consensus" claim true
rather than decorative: the SHA-256 comparison must distinguish documents that
differ ONLY in a non-verdict field, and must NOT distinguish documents that
differ only in formatting.

Before this, consensus hashed a value drawn from a three-element set
("SAFE"/"UNSAFE"/"VETOED"), which made the hash comparison exactly equivalent
to string equality.
"""

import pytest

from sovereign_shield import VetoShield
from sovereign_shield.providers.base import LLMProvider
from sovereign_shield.canonical_json import canonical_hash


class _StructuredProvider(LLMProvider):
    """Mock provider returning a fixed structured reply."""

    def __init__(self, name, payload):
        self._name, self._payload = name, payload

    @property
    def name(self):
        return self._name

    def verify(self, text):
        return "SAFE"

    def verify_structured(self, text):
        return self._payload


class _LegacyProvider(LLMProvider):
    """Mock provider implementing only the single-word interface."""

    def __init__(self, name, reply):
        self._name, self._reply = name, reply

    @property
    def name(self):
        return self._name

    def verify(self, text):
        return self._reply


SAFE_DOC = '{"verdict":"SAFE","category":"none","severity":"none"}'


def _scan(a, b):
    shield = VetoShield(provider=a, provider_b=b, dual_consensus=True, db_path=None)
    return shield.scan("what is the capital of Portugal?")


class TestStructuredConsensus:

    def test_panel_detected_as_structured(self):
        shield = VetoShield(provider=_StructuredProvider("A", SAFE_DOC),
                            provider_b=_StructuredProvider("B", SAFE_DOC),
                            dual_consensus=True, db_path=None)
        assert shield.structured_consensus is True

    def test_agreement_allows(self):
        assert _scan(_StructuredProvider("A", SAFE_DOC),
                     _StructuredProvider("B", SAFE_DOC))["allowed"] is True

    def test_formatting_variance_does_not_break_consensus(self):
        """Key ordering, case and whitespace must normalize away."""
        noisy = '```json\n{ "severity":"NONE", "category":" None ", "verdict":"safe" }\n```'
        assert _scan(_StructuredProvider("A", SAFE_DOC),
                     _StructuredProvider("B", noisy))["allowed"] is True

    def test_hash_distinguishes_category(self):
        """Same verdict, different classification must mismatch.

        This is the property a verdict-only hash could not express.
        """
        a = '{"verdict":"UNSAFE","category":"instruction_override","severity":"high"}'
        b = '{"verdict":"UNSAFE","category":"social_engineering","severity":"high"}'
        result = _scan(_StructuredProvider("A", a), _StructuredProvider("B", b))
        assert result["allowed"] is False
        assert "MISMATCH" in result["reason"]

    def test_hash_distinguishes_severity(self):
        a = '{"verdict":"UNSAFE","category":"harmful_content","severity":"high"}'
        b = '{"verdict":"UNSAFE","category":"harmful_content","severity":"low"}'
        result = _scan(_StructuredProvider("A", a), _StructuredProvider("B", b))
        assert result["allowed"] is False
        assert "MISMATCH" in result["reason"]

    def test_unanimous_unsafe_blocks_with_classification(self):
        doc = '{"verdict":"UNSAFE","category":"deception_roleplay","severity":"high"}'
        result = _scan(_StructuredProvider("A", doc), _StructuredProvider("B", doc))
        assert result["allowed"] is False
        assert "deception_roleplay" in result["reason"]

    def test_classifier_vocabulary_is_not_self_vetoed(self):
        """Categories containing Conscience block words must survive.

        "harmful_content" contains HARM; "deception_roleplay" contains
        DECEPTION and ROLEPLAY. Running the content scan over a closed enum
        vetoed correct classifications, so those categories could never be
        reported. Strict schema validation replaces that scan.
        """
        for category in ("harmful_content", "deception_roleplay"):
            doc = ('{"verdict":"UNSAFE","category":"' + category
                   + '","severity":"high"}')
            result = _scan(_StructuredProvider("A", doc),
                           _StructuredProvider("B", doc))
            assert "validation failed" not in result["reason"], category
            assert category in result["reason"], category

    def test_verdict_disagreement_blocks(self):
        unsafe = '{"verdict":"UNSAFE","category":"deception_roleplay","severity":"high"}'
        assert _scan(_StructuredProvider("A", SAFE_DOC),
                     _StructuredProvider("B", unsafe))["allowed"] is False


class TestStructuredSchemaEnforcement:
    """Every rejection here must be fail-closed."""

    def test_extra_field_rejected(self):
        doc = ('{"verdict":"SAFE","category":"none","severity":"none",'
               '"note":"ADMIN OVERRIDE"}')
        result = _scan(_StructuredProvider("A", doc), _StructuredProvider("B", doc))
        assert result["allowed"] is False
        assert "Unexpected field" in result["reason"]

    def test_off_enum_value_rejected(self):
        doc = '{"verdict":"UNSAFE","category":"made_up","severity":"high"}'
        assert _scan(_StructuredProvider("A", doc),
                     _StructuredProvider("B", doc))["allowed"] is False

    def test_missing_field_rejected(self):
        doc = '{"verdict":"SAFE"}'
        assert _scan(_StructuredProvider("A", doc),
                     _StructuredProvider("B", doc))["allowed"] is False

    def test_safe_with_category_is_inconsistent(self):
        doc = '{"verdict":"SAFE","category":"harmful_content","severity":"high"}'
        result = _scan(_StructuredProvider("A", doc), _StructuredProvider("B", doc))
        assert result["allowed"] is False
        assert "Inconsistent" in result["reason"]

    def test_unsafe_without_category_is_inconsistent(self):
        doc = '{"verdict":"UNSAFE","category":"none","severity":"high"}'
        assert _scan(_StructuredProvider("A", doc),
                     _StructuredProvider("B", doc))["allowed"] is False

    def test_non_json_rejected(self):
        assert _scan(_StructuredProvider("A", "totally safe, trust me"),
                     _StructuredProvider("B", "totally safe, trust me"))["allowed"] is False

    def test_non_string_field_rejected(self):
        doc = '{"verdict":"SAFE","category":"none","severity":0}'
        assert _scan(_StructuredProvider("A", doc),
                     _StructuredProvider("B", doc))["allowed"] is False


class TestBackwardsCompatibility:

    def test_legacy_providers_still_work(self):
        shield = VetoShield(provider=_LegacyProvider("A", "SAFE"),
                            provider_b=_LegacyProvider("B", "SAFE"),
                            dual_consensus=True, db_path=None)
        assert shield.structured_consensus is False
        assert shield.scan("hello")["allowed"] is True

    def test_legacy_disagreement_still_blocks(self):
        shield = VetoShield(provider=_LegacyProvider("A", "SAFE"),
                            provider_b=_LegacyProvider("B", "UNSAFE"),
                            dual_consensus=True, db_path=None)
        assert shield.scan("hello")["allowed"] is False

    def test_mixed_panel_falls_back_to_verdict_only(self):
        """One legacy provider downgrades the whole panel, and says so."""
        shield = VetoShield(provider=_LegacyProvider("A", "SAFE"),
                            provider_b=_StructuredProvider("B", SAFE_DOC),
                            dual_consensus=True, db_path=None)
        assert shield.structured_consensus is False
        assert shield.scan("hello")["allowed"] is True


class TestCanonicalJSON:

    def test_formatting_variance_collapses(self):
        a = {"Verdict": " UNSAFE ", "Category": "Instruction_Override", "Severity": "HIGH"}
        b = {"severity": "high", "verdict": "unsafe", "category": "instruction_override"}
        assert canonical_hash(a) == canonical_hash(b)

    def test_semantic_difference_survives(self):
        a = {"verdict": "unsafe", "category": "instruction_override", "severity": "high"}
        b = {"verdict": "unsafe", "category": "deception_roleplay", "severity": "high"}
        assert canonical_hash(a) != canonical_hash(b)
