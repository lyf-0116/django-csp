from django.http import (
    HttpResponse,
    HttpResponseNotFound,
    HttpResponseServerError,
)
from django.template import Context, Template, engines
from django.test import RequestFactory
from django.test.utils import override_settings

import pytest

from csp.constants import HEADER, HEADER_REPORT_ONLY, NONCE, SELF
from csp.exceptions import CSPNonceError
from csp.middleware import CheckableLazyObject, CSPMiddleware
from csp.tests.utils import response

mw = CSPMiddleware(response())
rf = RequestFactory()


def test_checkable_lazy_object() -> None:
    def generate_value() -> str:
        return "generated"

    lazy = CheckableLazyObject(generate_value)

    # Before wrapped object is initiated, lazy is falsy
    assert bool(lazy) is False

    # After str(lazy) calls generate_value, lazy is truthy
    assert str(lazy) == "generated"
    assert bool(lazy) is True


def test_add_header() -> None:
    request = rf.get("/")
    response = HttpResponse()
    mw.process_response(request, response)
    assert HEADER in response


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": ["example.com"]}},
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"default-src": [SELF]}},
)
def test_both_headers() -> None:
    request = rf.get("/")
    response = HttpResponse()
    mw.process_response(request, response)
    assert HEADER in response
    assert HEADER_REPORT_ONLY in response


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": {"example.com"}}},
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"default-src": {SELF}}},
)
def test_directives_configured_as_sets() -> None:
    request = rf.get("/")
    response = HttpResponse()
    mw.process_response(request, response)
    assert HEADER in response
    assert HEADER_REPORT_ONLY in response


def test_exempt() -> None:
    request = rf.get("/")
    response = HttpResponse()
    setattr(response, "_csp_exempt", True)
    mw.process_response(request, response)
    assert HEADER not in response


@override_settings(CONTENT_SECURITY_POLICY={"EXCLUDE_URL_PREFIXES": ["/inlines-r-us"]})
def test_exclude() -> None:
    request = rf.get("/inlines-r-us/foo")
    response = HttpResponse()
    mw.process_response(request, response)
    assert HEADER not in response


@override_settings(
    CONTENT_SECURITY_POLICY=None,
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"default-src": [SELF]}},
)
def test_report_only() -> None:
    request = rf.get("/")
    response = HttpResponse()
    mw.process_response(request, response)
    assert HEADER not in response
    assert HEADER_REPORT_ONLY in response
    assert response[HEADER_REPORT_ONLY] == "default-src 'self'"


def test_dont_replace() -> None:
    request = rf.get("/")
    response = HttpResponse()
    response[HEADER] = "default-src example.com"
    mw.process_response(request, response)
    assert response[HEADER] == "default-src example.com"


def test_use_config() -> None:
    request = rf.get("/")
    response = HttpResponse()
    setattr(response, "_csp_config", {"default-src": ["example.com"]})
    mw.process_response(request, response)
    assert response[HEADER] == "default-src example.com"


def test_use_update() -> None:
    request = rf.get("/")
    response = HttpResponse()
    setattr(response, "_csp_update", {"default-src": ["example.com"]})
    mw.process_response(request, response)
    assert response[HEADER] == "default-src 'self' example.com"


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"img-src": ["foo.com"]}})
def test_use_replace() -> None:
    request = rf.get("/")
    response = HttpResponse()
    setattr(response, "_csp_replace", {"img-src": ["bar.com"]})
    mw.process_response(request, response)
    policy_list = sorted(response[HEADER].split("; "))
    assert policy_list == ["default-src 'self'", "img-src bar.com"]


@override_settings(DEBUG=True)
def test_debug_errors_exempt() -> None:
    request = rf.get("/")
    response = HttpResponseServerError()
    mw.process_response(request, response)
    assert HEADER not in response


@override_settings(DEBUG=True)
def test_debug_notfound_exempt() -> None:
    request = rf.get("/")
    response = HttpResponseNotFound()
    mw.process_response(request, response)
    assert HEADER not in response


def test_nonce_created_when_accessed() -> None:
    request = rf.get("/")
    mw.process_request(request)
    nonce = str(getattr(request, "csp_nonce"))
    response = HttpResponse()
    mw.process_response(request, response)
    assert nonce in response[HEADER]
    assert response[HEADER] == f"default-src 'self' 'nonce-{nonce}'"


def test_nonce_is_generated_eagerly_and_truthy() -> None:
    request = rf.get("/")
    mw.process_request(request)
    # The nonce is finalized when the request enters, before anything reads it.
    nonce = getattr(request, "csp_nonce")
    assert isinstance(nonce, str) and nonce
    assert bool(getattr(request, "csp_nonce")) is True

    response = HttpResponse()
    mw.process_response(request, response)
    # The finalized nonce stays readable after the headers are written so
    # responses whose body renders late (streaming) still get the same value.
    assert bool(getattr(request, "csp_nonce")) is True
    assert getattr(request, "csp_nonce") == nonce


def test_nonce_conditional_in_django_template() -> None:
    """A finalized nonce is truthy in a Django template context"""

    template = Template(
        """
        {% if request.csp_nonce %}
          The CSP nonce is {{ request.csp_nonce }}.
        {% else %}
          The CSP nonce is not set.
        {% endif %}
    """
    )
    request = rf.get("/")
    context = Context({"request": request})

    mw.process_request(request)
    nonce = getattr(request, "csp_nonce")
    rendered_set = template.render(context).strip()
    assert rendered_set == f"The CSP nonce is {nonce}."


def test_nonce_usage_in_django_template() -> None:
    """The request nonce renders in a Django template"""

    template = Template("The CSP nonce is {{ request.csp_nonce }}.")
    request = rf.get("/")
    context = Context({"request": request})

    mw.process_request(request)
    nonce = getattr(request, "csp_nonce", None)
    assert isinstance(nonce, str) and bool(nonce) is True
    rendered = template.render(context)
    assert bool(nonce) is True
    assert rendered == f"The CSP nonce is {nonce}."


def test_nonce_conditional_in_jinja2_template() -> None:
    """A finalized nonce is truthy in a Jinja2 template context"""

    template = engines["jinja2"].from_string(
        """
        {% if request.csp_nonce %}
          The CSP nonce is {{ request.csp_nonce }}.
        {% else %}
          The CSP nonce is not set.
        {% endif %}
    """
    )
    request = rf.get("/")
    context = {"request": request}

    mw.process_request(request)
    nonce = getattr(request, "csp_nonce")
    rendered_set = template.render(context).strip()
    assert rendered_set == f"The CSP nonce is {nonce}."


def test_nonce_usage_in_jinja2_template() -> None:
    """The request nonce renders in a Jinja2 template"""

    template = engines["jinja2"].from_string("The CSP nonce is {{ request.csp_nonce }}.")
    request = rf.get("/")
    context = {"request": request}

    mw.process_request(request)
    nonce = getattr(request, "csp_nonce", None)
    assert isinstance(nonce, str) and bool(nonce) is True
    rendered = template.render(context)
    assert bool(nonce) is True
    assert rendered == f"The CSP nonce is {nonce}."


def test_nonce_always_included_in_header() -> None:
    request = rf.get("/")
    mw.process_request(request)
    response = HttpResponse()
    mw.process_response(request, response)
    nonce = getattr(request, "_csp_nonce")
    assert response[HEADER] == f"default-src 'self' 'nonce-{nonce}'"


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": [SELF, NONCE]}},
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"default-src": [SELF, NONCE]}},
)
def test_same_nonce_in_enforced_and_report_only_headers() -> None:
    request = rf.get("/")
    mw.process_request(request)
    nonce = getattr(request, "_csp_nonce")
    response = HttpResponse()
    mw.process_response(request, response)
    assert response[HEADER] == f"default-src 'self' 'nonce-{nonce}'"
    assert response[HEADER_REPORT_ONLY] == f"default-src 'self' 'nonce-{nonce}'"


def test_nonce_regenerated_on_new_request() -> None:
    request1 = rf.get("/")
    request2 = rf.get("/")
    mw.process_request(request1)
    mw.process_request(request2)
    nonce1 = str(getattr(request1, "csp_nonce"))
    nonce2 = str(getattr(request2, "csp_nonce"))
    assert nonce1 != nonce2

    response1 = HttpResponse()
    response2 = HttpResponse()
    mw.process_response(request1, response1)
    mw.process_response(request2, response2)
    assert nonce1 not in response2[HEADER]
    assert nonce2 not in response1[HEADER]


def test_missing_nonce_access_after_header_is_written_raises() -> None:
    # If no nonce was finalized before the headers were written (e.g.
    # process_request was skipped), reading it afterwards must raise instead of
    # silently rendering an empty nonce.
    request = rf.get("/")
    mw.process_response(request, HttpResponse())
    assert bool(getattr(request, "csp_nonce", True)) is False
    with pytest.raises(CSPNonceError):
        str(getattr(request, "csp_nonce"))


def test_finalized_nonce_read_after_header_is_still_available() -> None:
    # A finalized nonce remains readable after the headers are written.
    request = rf.get("/")
    mw.process_request(request)
    nonce = str(getattr(request, "csp_nonce"))
    response = HttpResponse()
    mw.process_response(request, response)
    assert nonce in response[HEADER]
    assert response[HEADER] == f"default-src 'self' 'nonce-{nonce}'"
    assert str(getattr(request, "csp_nonce")) == nonce


def test_streaming_response_nonce_matches_rendered_template() -> None:
    # Streaming responses write their headers before the response iterator
    # renders the body. The nonce embedded in the body's inline scripts must
    # still match the nonce in the CSP header.
    template = Template("<script nonce='{{ request.csp_nonce }}'>var hello='world';</script>")
    request = rf.get("/")
    mw.process_request(request)
    nonce = str(getattr(request, "csp_nonce"))

    response = HttpResponse()
    mw.process_response(request, response)

    # The body is rendered only after `process_response`, as with a streaming response.
    rendered_body = template.render(Context({"request": request}))
    assert f"nonce='{nonce}'" in rendered_body
    assert f"'nonce-{nonce}'" in response[HEADER]


def test_nonce_is_stable_within_a_request() -> None:
    request = rf.get("/")
    mw.process_request(request)
    first = getattr(request, "csp_nonce")
    second = getattr(request, "csp_nonce")
    assert first == second == getattr(request, "_csp_nonce")
