import json
import os
import socket
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase, override_settings

import requests
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.test import APIRequestFactory, force_authenticate

from aegis.models import RegisteredService
from aegis.serializers import CustomTokenObtainPairSerializer
from aegis.views.api.service_registry_views import (
    PROXY_RETRY_ATTEMPTS,
    NewReverseProxyAPIView,
    RegisterServiceAPIView,
    _call_upstream_with_retry,
)
from gatekeeper.env_helpers import PLACEHOLDER_SECRET_BLOCKLIST, get_secret_env_var


class ProxyForwardRetryTests(TestCase):
    """dispatch_request's upstream call retries transient connection
    failures (docker DNS churn during peer-container recreation surfaces as
    socket.gaierror, wrapped by requests as ConnectionError) but never
    retries an already-received HTTP response.
    """

    def test_retries_transient_gaierror_then_succeeds(self):
        gaierror = requests.exceptions.ConnectionError(
            socket.gaierror(-2, "Name or service not known")
        )
        success_response = Mock(spec=requests.Response)

        with patch(
            "aegis.views.api.service_registry_views.requests.request",
            side_effect=[gaierror, success_response],
        ) as mock_request:
            resp = _call_upstream_with_retry(
                "GET", "http://weathersrv:8010/api/", {}, "corr-1"
            )

        self.assertIs(resp, success_response)
        self.assertEqual(mock_request.call_count, 2)

    def test_gives_up_after_exhausting_retry_attempts(self):
        gaierror = requests.exceptions.ConnectionError(
            socket.gaierror(-2, "Name or service not known")
        )

        with patch(
            "aegis.views.api.service_registry_views.requests.request",
            side_effect=gaierror,
        ) as mock_request:
            with self.assertRaises(requests.exceptions.ConnectionError):
                _call_upstream_with_retry(
                    "GET", "http://weathersrv:8010/api/", {}, "corr-2"
                )

        self.assertEqual(mock_request.call_count, PROXY_RETRY_ATTEMPTS)

    def test_does_not_retry_an_upstream_http_response(self):
        upstream_500 = Mock(spec=requests.Response)
        upstream_500.status_code = 500

        with patch(
            "aegis.views.api.service_registry_views.requests.request",
            return_value=upstream_500,
        ) as mock_request:
            resp = _call_upstream_with_retry(
                "GET", "http://weathersrv:8010/api/", {}, "corr-3"
            )

        self.assertIs(resp, upstream_500)
        self.assertEqual(mock_request.call_count, 1)


class ProxyDispatchUnreachableUpstreamTests(TestCase):
    """An upstream that never answers
    at the connection level (DNS failure, refused connection, timeout —
    everything _call_upstream_with_retry retries and gives up on) must
    surface from GK as a distinguishable 502, not the generic 500 the
    outer `except Exception` returns for GK's own bugs. Callers (PDM's
    weather proxy) branch on this status to route into their degraded
    score-only path instead of treating it as an opaque failure.
    """

    def setUp(self):
        from django.test import RequestFactory

        RegisteredService.objects.create(
            base_url="http://weathersrv:8010/",
            service_name="weathersrv",
            endpoint="api/",
            methods=["GET"],
        )
        self.factory = RequestFactory()
        self.view = NewReverseProxyAPIView()

    def test_unreachable_upstream_returns_502_not_500(self):
        gaierror = requests.exceptions.ConnectionError(
            socket.gaierror(-2, "Name or service not known")
        )
        request = self.factory.get("/api/proxy/weathersrv/api/")

        with patch(
            "aegis.views.api.service_registry_views._call_upstream_with_retry",
            side_effect=gaierror,
        ):
            response = self.view.dispatch_request(request, "weathersrv/api/")

        self.assertEqual(response.status_code, 502)
        body = json.loads(response.content)
        self.assertIn("unreachable", body["error"].lower())


class ServiceRegistrationDedupTests(TestCase):
    """Registration dedup in
    RegisterServiceAPIView.post must key on exact endpoint-string equality,
    not match_endpoint's pattern semantics. Pattern matching a literal
    endpoint against a previously registered parameterized one is a false
    identity that overwrites the parameterized row: registering
    `openagri-report/{report_id}/` and then `openagri-report/pest-session-report/`
    for reporting would destroy the parameterized route and leave the
    report-download URL unroutable.

    Each test drives the real authenticated view (RegisterServiceAPIView,
    via DRF's request factory + force_authenticate) rather than
    reimplementing the dedup logic.
    """

    BASE_URL = "http://reportingsrv:8010/"
    SERVICE_NAME = "reporting"

    def setUp(self):
        self.factory = APIRequestFactory()
        self.user = get_user_model().objects.create_user(
            username="registrar", email="registrar@example.com", password="a-real-password"
        )
        self.view = RegisterServiceAPIView.as_view()

    def _register(self, endpoint, methods, base_url=None, service_name=None):
        request = self.factory.post(
            "/api/register_service/",
            {
                "base_url": base_url or self.BASE_URL,
                "service_name": service_name or self.SERVICE_NAME,
                "endpoint": endpoint,
                "methods": methods,
            },
            format="json",
        )
        force_authenticate(request, user=self.user)
        response = self.view(request)
        self.assertIn(response.status_code, (200, 201), response.content)
        return response

    def test_parameterized_and_literal_routes_coexist(self):
        self._register("openagri-report/{report_id}/", ["GET"])
        self._register("openagri-report/pest-session-report/", ["POST"])

        rows = RegisteredService.objects.filter(
            base_url=self.BASE_URL, service_name=self.SERVICE_NAME
        )
        self.assertEqual(rows.count(), 2)

        parameterized = rows.get(endpoint="openagri-report/{report_id}/")
        literal = rows.get(endpoint="openagri-report/pest-session-report/")
        self.assertEqual(set(parameterized.methods), {"GET"})
        self.assertEqual(set(literal.methods), {"POST"})

    def test_reannouncing_same_endpoint_updates_in_place(self):
        self._register("openagri-report/{report_id}/", ["GET"])
        self._register("openagri-report/{report_id}/", ["GET", "HEAD"])

        rows = RegisteredService.objects.filter(
            base_url=self.BASE_URL, service_name=self.SERVICE_NAME,
            endpoint="openagri-report/{report_id}/",
        )
        self.assertEqual(rows.count(), 1)
        self.assertEqual(set(rows.first().methods), {"GET", "HEAD"})

    def test_collapsed_deployment_heals_on_full_reannouncement(self):
        RegisteredService.objects.create(
            base_url=self.BASE_URL,
            service_name=self.SERVICE_NAME,
            endpoint="openagri-report/pest-session-report/",
            methods=["POST", "GET"],
        )

        self._register("openagri-report/{report_id}/", ["GET"])
        self._register("openagri-report/pest-session-report/", ["POST"])

        rows = RegisteredService.objects.filter(
            base_url=self.BASE_URL, service_name=self.SERVICE_NAME
        )
        self.assertEqual(rows.count(), 2)
        parameterized = rows.get(endpoint="openagri-report/{report_id}/")
        self.assertEqual(set(parameterized.methods), {"GET"})

        from django.test import RequestFactory

        concrete_id = "3fa85f64-5717-4562-b3fc-2c963f66afa6"
        request = RequestFactory().get(
            f"/api/proxy/{self.SERVICE_NAME}/openagri-report/{concrete_id}/"
        )
        mock_upstream_response = Mock(spec=requests.Response)
        mock_upstream_response.status_code = 200
        mock_upstream_response.headers = {}
        mock_upstream_response.iter_content = Mock(return_value=iter([b""]))

        with patch(
            "aegis.views.api.service_registry_views._call_upstream_with_retry",
            return_value=mock_upstream_response,
        ) as mock_call:
            response = NewReverseProxyAPIView().dispatch_request(
                request, f"{self.SERVICE_NAME}/openagri-report/{concrete_id}/"
            )

        self.assertEqual(response.status_code, 200)
        mock_call.assert_called_once()
        called_method, called_upstream_url = mock_call.call_args[0][:2]
        self.assertEqual(called_method, "GET")
        self.assertEqual(
            called_upstream_url, f"{self.BASE_URL}openagri-report/{concrete_id}/"
        )


class PlaceholderSecretBlocklistTests(TestCase):
    """`get_secret_env_var` -- used by
    `settings.py` for both `DJANGO_SECRET_KEY` and `JWT_SIGNING_KEY` --
    must refuse a known-placeholder value rather than let it through as a
    live secret. `settings.py` itself already ran (with GK's real
    configured secret) before this test suite started, so this exercises
    the same validation function directly rather than re-triggering
    Django's settings module import.
    """

    def test_each_known_placeholder_value_is_rejected(self):
        for placeholder in PLACEHOLDER_SECRET_BLOCKLIST:
            with self.subTest(placeholder=placeholder):
                with patch.dict(os.environ, {"TEST_SECRET_VAR": placeholder}):
                    with self.assertRaises(ImproperlyConfigured):
                        get_secret_env_var("TEST_SECRET_VAR")

    def test_placeholder_check_is_case_insensitive(self):
        with patch.dict(os.environ, {"TEST_SECRET_VAR": "Change-Me"}):
            with self.assertRaises(ImproperlyConfigured):
                get_secret_env_var("TEST_SECRET_VAR")

    def test_real_shaped_secret_is_accepted(self):
        with patch.dict(
            os.environ,
            {"TEST_SECRET_VAR": "a-real-unique-signing-secret-not-on-the-blocklist"},
        ):
            self.assertEqual(
                get_secret_env_var("TEST_SECRET_VAR"),
                "a-real-unique-signing-secret-not-on-the-blocklist",
            )

    def test_missing_var_raises_improperly_configured(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("TEST_SECRET_VAR_UNSET", None)
            with self.assertRaises(ImproperlyConfigured):
                get_secret_env_var("TEST_SECRET_VAR_UNSET")


class DefaultCredentialRejectionTests(TestCase):
    """The admin/admin login pair is rejected outside the demo profile
    (DEPLOYMENT_PROFILE != "demo", the default), and still works when a
    deployment explicitly opts into "demo"."""

    def setUp(self):
        get_user_model().objects.create_user(
            username="admin", email="admin@example.com", password="admin"
        )

    @override_settings(DEPLOYMENT_PROFILE="hardened")
    def test_admin_admin_rejected_in_hardened_profile(self):
        serializer = CustomTokenObtainPairSerializer(data={"username": "admin", "password": "admin"})
        with self.assertRaises(AuthenticationFailed):
            serializer.is_valid(raise_exception=True)

    @override_settings(DEPLOYMENT_PROFILE="demo")
    def test_admin_admin_accepted_in_demo_profile(self):
        serializer = CustomTokenObtainPairSerializer(data={"username": "admin", "password": "admin"})
        self.assertTrue(serializer.is_valid(raise_exception=True))
        self.assertIn("access", serializer.validated_data)

    @override_settings(DEPLOYMENT_PROFILE="hardened")
    def test_non_default_credentials_still_work_in_hardened_profile(self):
        get_user_model().objects.create_user(
            username="realuser", email="realuser@example.com", password="a-real-password"
        )
        serializer = CustomTokenObtainPairSerializer(data={"username": "realuser", "password": "a-real-password"})
        self.assertTrue(serializer.is_valid(raise_exception=True))
        self.assertIn("access", serializer.validated_data)
