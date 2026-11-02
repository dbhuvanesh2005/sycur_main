import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from sycur_rag.core.enums import PolicyAction, ReviewStatus, Severity
from sycur_rag.github.app_auth import create_app_jwt
from sycur_rag.github.check_publisher import publish_github_check_run
from sycur_rag.models.review import ReviewResult


class TestGitHubAppAuthenticationConfiguration(unittest.TestCase):

    @patch("sycur_rag.github.app_auth.get_settings")
    def test_missing_app_id_is_rejected(self, mock_get_settings):
        mock_get_settings.return_value = SimpleNamespace(
            GITHUB_APP_ID=None,
            GITHUB_APP_PRIVATE_KEY_PATH="/unused/test-key.pem",
        )

        with self.assertRaisesRegex(
            ValueError,
            "GitHub App ID is not configured",
        ):
            create_app_jwt()

    @patch("sycur_rag.github.app_auth.time.time", return_value=1_700_000_000)
    @patch("sycur_rag.github.app_auth.jwt.encode", return_value="test-jwt")
    @patch("sycur_rag.github.app_auth.Path.read_bytes", return_value=b"test-key")
    @patch("sycur_rag.github.app_auth.get_settings")
    def test_valid_app_id_is_used_as_jwt_issuer(
        self,
        mock_get_settings,
        _mock_read_bytes,
        mock_encode,
        _mock_time,
    ):
        mock_get_settings.return_value = SimpleNamespace(
            GITHUB_APP_ID=5_441_706,
            GITHUB_APP_PRIVATE_KEY_PATH="/unused/test-key.pem",
        )

        token = create_app_jwt()

        self.assertEqual(token, "test-jwt")
        mock_encode.assert_called_once_with(
            {
                "iat": 1_699_999_940,
                "exp": 1_700_000_540,
                "iss": "5441706",
            },
            b"test-key",
            algorithm="RS256",
        )

    @patch("sycur_rag.github.app_auth.get_settings")
    def test_missing_private_key_path_is_rejected(self, mock_get_settings):
        mock_get_settings.return_value = SimpleNamespace(
            GITHUB_APP_ID=5_441_706,
            GITHUB_APP_PRIVATE_KEY_PATH=None,
        )

        with self.assertRaisesRegex(
            ValueError,
            "GitHub App private key path is not configured",
        ):
            create_app_jwt()


class TestGitHubCheckPublisherConfiguration(unittest.TestCase):

    def setUp(self):
        self.review = ReviewResult(
            status=ReviewStatus.PASS,
            action=PolicyAction.ALLOW,
            severity=Severity.NOT_APPLICABLE,
            reason="No findings.",
        )

    @patch("sycur_rag.github.check_publisher.create_installation_access_token")
    @patch("sycur_rag.github.check_publisher.get_settings")
    def test_missing_app_id_is_rejected_before_authentication(
        self,
        mock_get_settings,
        mock_create_token,
    ):
        mock_get_settings.return_value = SimpleNamespace(GITHUB_APP_ID=None)

        with self.assertRaisesRegex(
            ValueError,
            "GitHub App ID is not configured",
        ):
            publish_github_check_run(
                repository="owner/repository",
                installation_id=1,
                head_sha="a" * 40,
                review=self.review,
                pr_number=1,
            )

        mock_create_token.assert_not_called()

    @patch("sycur_rag.github.check_publisher.json.load")
    @patch("sycur_rag.github.check_publisher.urlopen")
    @patch("sycur_rag.github.check_publisher.find_existing_github_check_run")
    @patch("sycur_rag.github.check_publisher.create_installation_access_token")
    @patch("sycur_rag.github.check_publisher.get_settings")
    def test_publisher_uses_centralized_app_id(
        self,
        mock_get_settings,
        mock_create_token,
        mock_find_existing,
        mock_urlopen,
        mock_json_load,
    ):
        mock_get_settings.return_value = SimpleNamespace(
            GITHUB_APP_ID=5_441_706,
        )
        mock_create_token.return_value = "test-installation-token"
        mock_find_existing.return_value = None
        response = MagicMock(status=201)
        mock_urlopen.return_value.__enter__.return_value = response
        mock_json_load.return_value = {
            "id": 10,
            "html_url": "https://example.invalid/check/10",
        }

        result = publish_github_check_run(
            repository="owner/repository",
            installation_id=1,
            head_sha="a" * 40,
            review=self.review,
            pr_number=1,
        )

        self.assertEqual(result["id"], 10)
        mock_find_existing.assert_called_once_with(
            repository="owner/repository",
            head_sha="a" * 40,
            token="test-installation-token",
            app_id=5_441_706,
            external_id=(
                "sycur:pr:owner/repository:1:"
                + "a" * 40
            ),
        )
        mock_urlopen.assert_called_once()


if __name__ == "__main__":
    unittest.main()
