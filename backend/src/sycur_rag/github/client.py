from __future__ import annotations

import time
from collections.abc import Callable
from urllib.parse import quote, urljoin, urlparse

import requests


RETRYABLE_STATUS_CODES = {
    408,
    429,
    500,
    502,
    503,
    504,
}


class GitHubAPIError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
    ) -> None:
        super().__init__(
            message
        )

        self.status_code = (
            status_code
        )


class GitHubClient:
    def __init__(
        self,
        *,
        token: str,
        base_url: str = (
            "https://api.github.com"
        ),
        timeout_seconds: float = 30.0,
        max_retries: int = 3,
        max_pages: int = 100,
        session: requests.Session | None = None,
        sleep: Callable[
            [float],
            None,
        ] = time.sleep,
    ) -> None:
        if not isinstance(
            token,
            str,
        ):
            raise TypeError(
                "GitHub token must be "
                "a string."
            )

        cleaned_token = token.strip()

        if not cleaned_token:
            raise ValueError(
                "GitHub token cannot "
                "be empty."
            )

        if not isinstance(
            base_url,
            str,
        ):
            raise TypeError(
                "base_url must be "
                "a string."
            )

        cleaned_base_url = (
            base_url.strip().rstrip(
                "/"
            )
        )

        parsed_base = urlparse(
            cleaned_base_url
        )

        if (
            parsed_base.query
            or parsed_base.fragment
            or parsed_base.username
            or parsed_base.password
        ):
            raise ValueError(
                "base_url must not contain "
                "query parameters, fragments, "
                "or user credentials."
            )

        hostname = (
            parsed_base.hostname or ""
        ).lower()

        local_hosts = {
            "localhost",
            "127.0.0.1",
            "::1",
        }

        if (
            parsed_base.scheme == "http"
            and hostname not in local_hosts
        ):
            raise ValueError(
                "base_url must use HTTPS "
                "except for local development."
            )

        if (
            parsed_base.scheme
            not in {
                "http",
                "https",
            }
            or not parsed_base.netloc
        ):
            raise ValueError(
                "base_url must be a "
                "valid HTTP(S) URL."
            )

        if (
            not isinstance(
                timeout_seconds,
                (int, float),
            )
            or isinstance(
                timeout_seconds,
                bool,
            )
            or timeout_seconds <= 0
        ):
            raise ValueError(
                "timeout_seconds must "
                "be positive."
            )

        if (
            not isinstance(
                max_retries,
                int,
            )
            or isinstance(
                max_retries,
                bool,
            )
            or max_retries < 0
        ):
            raise ValueError(
                "max_retries must be "
                "a non-negative integer."
            )

        if (
            not isinstance(
                max_pages,
                int,
            )
            or isinstance(
                max_pages,
                bool,
            )
            or max_pages <= 0
        ):
            raise ValueError(
                "max_pages must be a "
                "positive integer."
            )

        if not callable(
            sleep
        ):
            raise TypeError(
                "sleep must be callable."
            )

        self._token = (
            cleaned_token
        )

        self._base_url = (
            cleaned_base_url
        )

        self._timeout_seconds = float(
            timeout_seconds
        )

        self._max_retries = (
            max_retries
        )

        self._max_pages = (
            max_pages
        )

        self._session = (
            session
            if session is not None
            else requests.Session()
        )

        self._sleep = sleep

    @property
    def base_url(
        self,
    ) -> str:
        return self._base_url

    def _headers(
        self,
    ) -> dict[str, str]:
        return {
            "Accept": (
                "application/"
                "vnd.github+json"
            ),
            "Authorization": (
                f"Bearer {self._token}"
            ),
            "X-GitHub-Api-Version": (
                "2022-11-28"
            ),
            "User-Agent": (
                "SYCUR"
            ),
        }

    def _build_url(
        self,
        path: str,
    ) -> str:
        if not isinstance(
            path,
            str,
        ):
            raise TypeError(
                "GitHub API path "
                "must be a string."
            )

        cleaned = path.strip()

        if not cleaned:
            raise ValueError(
                "GitHub API path "
                "cannot be empty."
            )

        if cleaned.startswith(
            (
                "http://",
                "https://",
            )
        ):
            url = cleaned
        else:
            url = urljoin(
                self._base_url + "/",
                cleaned.lstrip("/"),
            )

        self._validate_pagination_url(
            url
        )

        return url

    def _validate_pagination_url(
        self,
        url: str,
    ) -> None:
        base = urlparse(
            self._base_url
        )

        candidate = urlparse(
            url
        )

        if (
            candidate.scheme
            != base.scheme
            or candidate.netloc
            != base.netloc
        ):
            raise GitHubAPIError(
                "GitHub pagination URL "
                "escaped the configured "
                "API origin."
            )

        base_path = base.path.rstrip("/")
        candidate_path = candidate.path.rstrip("/")

        if base_path:
            if not (
                candidate_path == base_path
                or candidate_path.startswith(
                    base_path + "/"
                )
            ):
                raise GitHubAPIError(
                    "GitHub pagination URL "
                    "escaped the configured "
                    "API base path."
                )

    @staticmethod
    def _repository_path(
        repository: str,
    ) -> str:
        if not isinstance(
            repository,
            str,
        ):
            raise TypeError(
                "repository must be "
                "a string."
            )

        cleaned = repository.strip()

        parts = cleaned.split(
            "/"
        )

        if (
            len(parts) != 2
            or not parts[0]
            or not parts[1]
        ):
            raise ValueError(
                "repository must use "
                "'owner/repository' "
                "format."
            )

        if any(
            part in {
                ".",
                "..",
            }
            for part in parts
        ):
            raise ValueError(
                "repository contains "
                "an invalid path segment."
            )

        owner, repo = parts

        return (
            f"{quote(owner, safe='')}/"
            f"{quote(repo, safe='')}"
        )

    @staticmethod
    def _pull_request_number(
        value: int,
    ) -> int:
        if (
            not isinstance(
                value,
                int,
            )
            or isinstance(
                value,
                bool,
            )
            or value <= 0
        ):
            raise ValueError(
                "pull_request_number "
                "must be a positive "
                "integer."
            )

        return value

    @staticmethod
    def _is_rate_limit_response(
        response: requests.Response,
    ) -> bool:
        if response.status_code != 403:
            return False

        retry_after = (
            response.headers.get(
                "Retry-After"
            )
        )

        remaining = (
            response.headers.get(
                "X-RateLimit-Remaining"
            )
        )

        return (
            retry_after is not None
            or remaining == "0"
        )

    def _should_retry_response(
        self,
        response: requests.Response,
    ) -> bool:
        return (
            response.status_code
            in RETRYABLE_STATUS_CODES
            or self._is_rate_limit_response(
                response
            )
        )

    @staticmethod
    def _retry_delay(
        *,
        response: requests.Response | None,
        attempt: int,
    ) -> float:
        if response is not None:
            retry_after = (
                response.headers.get(
                    "Retry-After"
                )
            )

            if retry_after is not None:
                try:
                    delay = float(
                        retry_after
                    )

                    if delay >= 0:
                        return min(
                            delay,
                            60.0,
                        )

                except ValueError:
                    pass

        # Bounded exponential backoff:
        # 1s, 2s, 4s, 8s...
        return min(
            float(
                2 ** attempt
            ),
            30.0,
        )

    def _request_json(
        self,
        *,
        url: str,
        params: dict[
            str,
            object,
        ] | None = None,
    ) -> tuple[
        object,
        requests.Response,
    ]:
        request_url = (
            self._build_url(
                url
            )
        )

        last_error: Exception | None = (
            None
        )

        for attempt in range(
            self._max_retries + 1
        ):
            response: (
                requests.Response
                | None
            ) = None

            try:
                response = (
                    self._session.get(
                        request_url,
                        headers=self._headers(),
                        params=params,
                        timeout=(
                            self._timeout_seconds
                        ),
                    )
                )

            except (
                requests.Timeout,
                requests.ConnectionError,
            ) as exc:
                last_error = exc

                if (
                    attempt
                    >= self._max_retries
                ):
                    break

                self._sleep(
                    self._retry_delay(
                        response=None,
                        attempt=attempt,
                    )
                )

                continue

            if (
                self._should_retry_response(
                    response
                )
            ):
                if (
                    attempt
                    >= self._max_retries
                ):
                    raise GitHubAPIError(
                        "GitHub API request "
                        "failed after retries "
                        f"with HTTP "
                        f"{response.status_code}.",
                        status_code=(
                            response.status_code
                        ),
                    )

                self._sleep(
                    self._retry_delay(
                        response=response,
                        attempt=attempt,
                    )
                )

                continue

            if not (
                200
                <= response.status_code
                < 300
            ):
                raise GitHubAPIError(
                    "GitHub API request "
                    "failed with HTTP "
                    f"{response.status_code}.",
                    status_code=(
                        response.status_code
                    ),
                )

            try:
                payload = response.json()

            except (
                ValueError,
                requests.JSONDecodeError,
            ) as exc:
                raise GitHubAPIError(
                    "GitHub API returned "
                    "invalid JSON.",
                    status_code=(
                        response.status_code
                    ),
                ) from exc

            return (
                payload,
                response,
            )

        raise GitHubAPIError(
            "GitHub API request failed "
            "after network retries."
        ) from last_error

    def get_repository(
        self,
        *,
        repository: str,
    ) -> dict:
        repo = self._repository_path(
            repository
        )

        payload, _ = self._request_json(
            url=f"/repos/{repo}"
        )

        if not isinstance(
            payload,
            dict,
        ):
            raise GitHubAPIError(
                "GitHub repository response "
                "must be an object."
            )

        if (
            not isinstance(
                payload.get("full_name"),
                str,
            )
            or payload["full_name"].casefold()
            != repository.casefold()
        ):
            raise GitHubAPIError(
                "GitHub returned an "
                "unexpected repository."
            )

        return payload

    def get_pull_request(
        self,
        *,
        repository: str,
        pull_request_number: int,
    ) -> dict:
        repo = self._repository_path(
            repository
        )

        number = (
            self._pull_request_number(
                pull_request_number
            )
        )

        payload, _ = (
            self._request_json(
                url=(
                    f"/repos/{repo}/"
                    f"pulls/{number}"
                )
            )
        )

        if not isinstance(
            payload,
            dict,
        ):
            raise GitHubAPIError(
                "GitHub pull request "
                "response must be "
                "an object."
            )

        return payload

    def list_pull_request_file_pages(
        self,
        *,
        repository: str,
        pull_request_number: int,
    ) -> list[list[object]]:
        repo = self._repository_path(
            repository
        )

        number = (
            self._pull_request_number(
                pull_request_number
            )
        )

        url = (
            f"/repos/{repo}/"
            f"pulls/{number}/files"
        )

        params: dict[
            str,
            object,
        ] | None = {
            "per_page": 100,
        }

        pages: list[
            list[object]
        ] = []

        seen_urls: set[str] = set()

        for _ in range(
            self._max_pages
        ):
            resolved_url = (
                self._build_url(
                    url
                )
            )

            if resolved_url in seen_urls:
                raise GitHubAPIError(
                    "GitHub pagination "
                    "loop detected."
                )

            seen_urls.add(
                resolved_url
            )

            payload, response = (
                self._request_json(
                    url=resolved_url,
                    params=params,
                )
            )

            if not isinstance(
                payload,
                list,
            ):
                raise GitHubAPIError(
                    "GitHub changed-files "
                    "response must be "
                    "an array."
                )

            pages.append(
                payload
            )

            next_link = (
                response.links
                .get(
                    "next",
                    {},
                )
                .get(
                    "url"
                )
            )

            if next_link is None:
                return pages

            if not isinstance(
                next_link,
                str,
            ):
                raise GitHubAPIError(
                    "GitHub pagination next "
                    "URL must be a string."
                )

            self._validate_pagination_url(
                next_link
            )

            url = next_link

            # GitHub's next URL already
            # contains its query string.
            params = None

        raise GitHubAPIError(
            "GitHub changed-files "
            "pagination exceeded the "
            f"configured maximum of "
            f"{self._max_pages} pages."
        )
