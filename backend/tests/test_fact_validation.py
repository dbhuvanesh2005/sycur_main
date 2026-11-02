import unittest

from sycur_rag.evidence.pack import (
    EvidencePack,
    EvidenceSource,
)
from sycur_rag.fact_validation import (
    validate_grounded_facts,
)


def make_evidence_pack(cwe_ids=()):
    source = EvidenceSource(
        source_id=1,
        title="Security Guidance",
        content=(
            "General security guidance for "
            "application input validation and remediation."
        ),
        document_name="Security Policy.pdf",
        framework=None,
        layer=None,
        language=None,
        topic=None,
        subtopic=None,
        control_id=None,
        cwe_ids=tuple(cwe_ids),
        source_path=None,
        chunk_index=None,
        content_hash="a" * 64,
        estimated_tokens=20,
        retrieval_signals=("keyword",),
        keyword_rank=1,
        vector_rank=None,
        graph_rank=None,
        graph_depth=None,
        graph_matched_seeds=(),
    )

    return EvidencePack(
        query_text="Security validation test",
        sources=(source,),
        estimated_tokens=20,
        token_budget=100,
        selection_strategy="test",
        excluded_count=0,
    )


def validate(
    summary,
    trusted_cwe_ids=(),
    evidence_pack=None,
):
    return validate_grounded_facts(
        finding_summary=summary,
        risk_explanation="The finding requires review.",
        required_action="Review the affected implementation.",
        source_ids=[1],
        evidence_pack=(
            evidence_pack or make_evidence_pack()
        ),
        trusted_cwe_ids=trusted_cwe_ids,
    )


class TestFactValidation(unittest.TestCase):

    def test_trusted_scanner_cwe_is_accepted(self):
        result = validate(
            "The finding is classified as CWE-130.",
            trusted_cwe_ids=("CWE-130",),
        )

        self.assertTrue(result.is_valid)
        self.assertEqual(
            result.unsupported_identifiers,
            (),
        )

    def test_untrusted_cwe_is_rejected(self):
        result = validate(
            "The finding is classified as CWE-999999."
        )

        self.assertIn(
            "CWE-999999",
            result.unsupported_identifiers,
        )

    def test_cwe_supported_by_evidence_is_accepted(self):
        result = validate(
            "The finding is classified as CWE-130.",
            evidence_pack=make_evidence_pack(
                ("CWE-130",)
            ),
        )

        self.assertTrue(result.is_valid)

    def test_cwe_identifier_is_not_extracted_as_acronym(self):
        result = validate(
            "The finding is classified as CWE-130."
        )

        self.assertNotIn(
            "CWE",
            result.checked_terms,
        )

    def test_standard_technical_terms_are_accepted(self):
        result = validate(
            "The API endpoint uses TLS and CWE terminology."
        )

        self.assertTrue(result.is_valid)

        self.assertEqual(
            result.unsupported_terms,
            (),
        )

    def test_unsupported_acronym_is_rejected(self):
        result = validate(
            "The implementation uses JWT."
        )

        self.assertIn(
            "JWT",
            result.unsupported_terms,
        )

    def test_unsupported_owasp_identifier_is_rejected(self):
        result = validate(
            "The issue maps to A01:2021."
        )

        self.assertIn(
            "A01:2021",
            result.unsupported_identifiers,
        )

    def test_unsupported_framework_is_rejected(self):
        result = validate(
            "The implementation follows OWASP Top 10."
        )

        self.assertIn(
            "OWASP Top 10",
            result.unsupported_frameworks,
        )

    def test_forbidden_policy_decision_is_rejected(self):
        result = validate(
            "Status is PASS."
        )

        self.assertFalse(result.is_valid)
        self.assertTrue(
            result.forbidden_policy_claims
        )

    def test_invalid_trusted_cwe_is_rejected(self):
        with self.assertRaises(ValueError):
            validate(
                "Security finding.",
                trusted_cwe_ids=("CWE-INVALID",),
            )


if __name__ == "__main__":
    unittest.main()
