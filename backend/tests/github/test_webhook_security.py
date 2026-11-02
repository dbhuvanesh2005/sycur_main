import hashlib
import hmac
import unittest

from sycur_rag.github.webhook_security import verify_github_signature


class TestGitHubWebhookSignature(unittest.TestCase):

    def setUp(self):
        self.secret = "test-secret-only"
        self.payload = b'{"action":"opened"}'

        self.valid_signature = "sha256=" + hmac.new(
            self.secret.encode("utf-8"),
            self.payload,
            hashlib.sha256,
        ).hexdigest()

    def test_valid_signature(self):
        self.assertTrue(
            verify_github_signature(
                self.payload,
                self.valid_signature,
                self.secret,
            )
        )

    def test_valid_empty_payload(self):
        empty_payload = b""
        signature = "sha256=" + hmac.new(
            self.secret.encode("utf-8"),
            empty_payload,
            hashlib.sha256,
        ).hexdigest()
        self.assertTrue(
            verify_github_signature(
                empty_payload,
                signature,
                self.secret,
            )
        )

    def test_invalid_signature(self):
        self.assertFalse(
            verify_github_signature(
                self.payload,
                "sha256=" + "0" * 64,
                self.secret,
            )
        )

    def test_wrong_signature_prefix(self):
        signature = self.valid_signature.replace(
            "sha256=", "sha1=", 1
        )
        self.assertFalse(
            verify_github_signature(
                self.payload, signature, self.secret
            )
        )

    def test_malformed_signature(self):
        self.assertFalse(
            verify_github_signature(
                self.payload, "sha256=invalid", self.secret
            )
        )

    def test_missing_signature(self):
        self.assertFalse(
            verify_github_signature(
                self.payload,
                None,
                self.secret,
            )
        )

    def test_wrong_secret(self):
        self.assertFalse(
            verify_github_signature(
                self.payload,
                self.valid_signature,
                "wrong-secret",
            )
        )

    def test_modified_payload(self):
        self.assertFalse(
            verify_github_signature(
                b'{"action":"closed"}',
                self.valid_signature,
                self.secret,
            )
        )


if __name__ == "__main__":
    unittest.main()
