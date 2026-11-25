from __future__ import annotations

import copy
import re
from collections.abc import Mapping
from itertools import chain
from typing import Any, Callable

from django.conf import settings
from django.utils.encoding import force_str

from csp.constants import NONCE, NONE, SELF

DEFAULT_DIRECTIVES = {
    # Fetch Directives
    "child-src": None,
    "connect-src": None,
    "default-src": [SELF],
    "script-src": None,
    "script-src-attr": None,
    "script-src-elem": None,
    "object-src": None,
    "style-src": None,
    "style-src-attr": None,
    "style-src-elem": None,
    "font-src": None,
    "frame-src": None,
    "img-src": None,
    "manifest-src": None,
    "media-src": None,
    "prefetch-src": None,  # Deprecated.
    # Document Directives
    "base-uri": None,
    "plugin-types": None,  # Deprecated.
    "sandbox": None,
    # Navigation Directives
    "form-action": None,
    "frame-ancestors": None,
    "navigate-to": None,
    # Reporting Directives
    "report-uri": None,
    "report-to": None,
    "require-sri-for": None,
    # Trusted Types Directives
    "require-trusted-types-for": None,
    "trusted-types": None,
    # Other Directives
    "webrtc": None,
    "worker-src": None,
    # Directives Defined in Other Documents
    "upgrade-insecure-requests": False,
    "block-all-mixed-content": False,  # Deprecated.
}

DIRECTIVES_T = dict[str, Any]
POLICY_T = dict[str, list[str]]


# Source directives fall back through these chains when a more specific
# directive is absent. See https://www.w3.org/TR/CSP3/#directive-fallback-list.
FALLBACK_CHAINS: dict[str, tuple[str, ...]] = {
    "default-src": ("default-src",),
    "script-src": ("script-src", "default-src"),
    "script-src-elem": ("script-src-elem", "script-src", "default-src"),
    "script-src-attr": ("script-src-attr", "script-src", "default-src"),
    "style-src": ("style-src", "default-src"),
    "style-src-elem": ("style-src-elem", "style-src", "default-src"),
    "style-src-attr": ("style-src-attr", "style-src", "default-src"),
    "child-src": ("child-src", "default-src"),
    "connect-src": ("connect-src", "default-src"),
    "font-src": ("font-src", "default-src"),
    "img-src": ("img-src", "default-src"),
    "manifest-src": ("manifest-src", "default-src"),
    "media-src": ("media-src", "default-src"),
    "object-src": ("object-src", "default-src"),
    "prefetch-src": ("prefetch-src", "default-src"),
    "frame-src": ("frame-src", "child-src", "default-src"),
    "worker-src": ("worker-src", "child-src", "script-src", "default-src"),
}

REPORTING_DIRECTIVES = frozenset({"report-uri", "report-to"})
BOOLEAN_DIRECTIVES = frozenset({"upgrade-insecure-requests", "block-all-mixed-content"})
# Requiring SRI for more resource types is stricter, so these tokens are additive.
ADDITIVE_NON_SOURCE_DIRECTIVES = frozenset({"require-sri-for"})


def default_config(csp: DIRECTIVES_T | None) -> DIRECTIVES_T | None:
    if csp is None:
        return None
    # Make a copy of the passed in config to avoid mutating it, and also to drop any unknown keys.
    config = {}
    for key, value in DEFAULT_DIRECTIVES.items():
        config[key] = csp.get(key, value)
    return config


def parse_policy(policy: str | DIRECTIVES_T | None) -> POLICY_T:
    """Parse a serialized CSP policy into directive/value lists."""
    if policy is None:
        return {}

    if isinstance(policy, Mapping):
        parsed: POLICY_T = {}
        for directive, value in policy.items():
            name = str(directive).lower()
            if value is None or value is False:
                continue
            if value is True:
                parsed[name] = []
            elif isinstance(value, (list, tuple, set)):
                parsed[name] = [str(item) for item in value]
            else:
                parsed[name] = [str(value)]
        return parsed

    parsed = {}
    for chunk in str(policy).split(";"):
        tokens = chunk.strip().split(None, 1)
        if not tokens:
            continue
        directive = tokens[0].lower()
        values = tokens[1].split() if len(tokens) > 1 else []
        # A serialized policy normally does not repeat a directive. Keep the
        # first value, matching browser handling of a policy-local duplicate.
        parsed.setdefault(directive, values)
    return parsed


def serialize_policy(policy: POLICY_T | DIRECTIVES_T) -> str:
    """Serialize a parsed policy using a stable directive order."""
    known_directives = [name for name in DEFAULT_DIRECTIVES if name in policy]
    extra_directives = sorted(name for name in policy if name not in DEFAULT_DIRECTIVES)

    parts = []
    for directive in known_directives + extra_directives:
        raw_values = policy[directive]
        if isinstance(raw_values, (list, tuple, set)):
            values = [str(value) for value in raw_values]
        elif raw_values is None or raw_values is False:
            continue
        elif raw_values is True:
            values = []
        else:
            values = [str(raw_values)]
        values = _dedupe_tokens(values)
        parts.append(" ".join((directive, *values)) if values else directive)

    return "; ".join(parts)


def _same_token(left: str, right: str) -> bool:
    if left == right:
        return True

    # Nonces and hashes are case-sensitive. Other source expressions and
    # CSP keyword names compare case-insensitively.
    sensitive_prefixes = ("'nonce-", "'sha256-", "'sha384-", "'sha512-")
    if left.startswith(sensitive_prefixes) or right.startswith(sensitive_prefixes):
        return False

    return left.lower() == right.lower()


def _dedupe_tokens(tokens: list[str]) -> list[str]:
    result: list[str] = []
    for token in tokens:
        if not any(_same_token(token, existing) for existing in result):
            result.append(token)
    return result


def _has_none(tokens: list[str]) -> bool:
    return any(token.lower() == NONE for token in tokens)


def _has_wildcard(tokens: list[str]) -> bool:
    return any(token == "*" for token in tokens)


def _effective_values(policy: POLICY_T, directive: str) -> list[str] | None:
    for candidate in FALLBACK_CHAINS.get(directive, (directive,)):
        if candidate in policy:
            return policy[candidate]
    return None


def _normalize_source_values(values: list[str]) -> list[str]:
    values = _dedupe_tokens(values)
    if any(value.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for value in values):
        # A nonce or hash makes 'unsafe-inline' ignored by CSP2+ browsers.
        # Drop it so older browsers do not receive the weaker expression.
        values = [value for value in values if value.lower() != "'unsafe-inline'"]
    return values


def _merge_source_values(left: list[str], right: list[str], *, strict: bool) -> list[str]:
    if not left or not right or _has_none(left) or _has_none(right):
        return [NONE]

    if _has_wildcard(left):
        # '*' subsumes every other source expression, so the other side is
        # the stricter effective list.
        return _normalize_source_values([*right])
    if _has_wildcard(right):
        return _normalize_source_values([*left])

    if strict:
        merged: list[str] = []
        for left_token in left:
            for right_token in right:
                if _same_token(left_token, right_token):
                    if not any(_same_token(left_token, existing) for existing in merged):
                        merged.append(left_token)
                    break
        if not merged:
            return [NONE]
    else:
        merged = [*left]
        for token in right:
            if not any(_same_token(token, existing) for existing in merged):
                merged.append(token)

    return _normalize_source_values(merged)


def _merge_directive(directive: str, left: list[str], right: list[str], *, strict: bool) -> list[str]:
    if directive in REPORTING_DIRECTIVES or directive in ADDITIVE_NON_SOURCE_DIRECTIVES:
        return _dedupe_tokens([*left, *right])

    if directive in BOOLEAN_DIRECTIVES:
        return []

    if directive == "sandbox":
        # Sandbox tokens are permissions, so the effective sandbox has the
        # intersection of the granted permissions. An empty list means a bare
        # ``sandbox`` directive, which is the strictest value.
        if not left or not right:
            return []
        merged = [token for token in left if any(_same_token(token, other) for other in right)]
        return _dedupe_tokens(merged)

    return _merge_source_values(left, right, strict=strict)


def merge_policies(*policies: str | DIRECTIVES_T | None, strict: bool = False) -> str:
    """
    Merge serialized CSP policies into one serialized policy.

    The default mode composes policy contributions: source lists are combined,
    fallback chains are resolved, and known conflicts are normalized toward the
    stricter expression. ``strict=True`` approximates what browsers do with
    multiple headers by intersecting source lists; an empty intersection becomes
    ``'none'``. Reporting endpoints are always combined.
    """
    parsed_policies: list[POLICY_T] = []
    for policy in policies:
        if isinstance(policy, Mapping):
            parsed_policies.append(parse_policy(policy))
        elif policy:
            # A header may itself contain comma-separated policies.
            for serialized_policy in str(policy).split(","):
                if serialized_policy.strip():
                    parsed_policies.append(parse_policy(serialized_policy))

    if not parsed_policies:
        return ""

    merged = parsed_policies[0]
    for policy in parsed_policies[1:]:
        next_merged: POLICY_T = {}
        for directive in set(merged) | set(policy):
            left = _effective_values(merged, directive)
            right = _effective_values(policy, directive)

            if left is None:
                if right is not None:
                    next_merged[directive] = list(right)
                continue
            if right is None:
                next_merged[directive] = list(left)
                continue

            next_merged[directive] = _merge_directive(directive, left, right, strict=strict)

        merged = next_merged

    return serialize_policy(merged)


# Descriptive aliases for callers and tests that use the longer name.
merge_policy = merge_policies
merge_csp_policies = merge_policies


def build_policy(
    config: DIRECTIVES_T | None = None,
    update: DIRECTIVES_T | None = None,
    replace: DIRECTIVES_T | None = None,
    nonce: str | None = None,
    report_only: bool = False,
) -> str:
    """Builds the policy as a string from the settings."""

    if config is None:
        if report_only:
            config = getattr(settings, "CONTENT_SECURITY_POLICY_REPORT_ONLY", {})
            config = default_config(config.get("DIRECTIVES", {})) if config else None
        else:
            config = getattr(settings, "CONTENT_SECURITY_POLICY", {})
            config = default_config(config.get("DIRECTIVES", {})) if config else None

    # If config is still `None`, return empty policy.
    if config is None:
        return ""

    update = update if update is not None else {}
    replace = replace if replace is not None else {}

    csp = {}

    for k in set(chain(config, replace)):
        if k in replace:
            v = replace[k]
        else:
            v = config[k]
        if v is not None:
            v = copy.copy(v)
            if isinstance(v, set):
                v = sorted(v)
            if not isinstance(v, (list, tuple)):
                v = (v,)
            csp[k] = v

    for k, v in update.items():
        if v is not None:
            v = copy.copy(v)
            if isinstance(v, set):
                v = sorted(v)
            if not isinstance(v, (list, tuple)):
                v = (v,)
            if csp.get(k) is None:
                csp[k] = v
            else:
                csp[k] += tuple(v)

    report_uri = csp.pop("report-uri", None)

    policy_parts = {}

    for key, value in csp.items():
        # Check for boolean directives.
        if len(value) == 1 and isinstance(value[0], bool):
            if value[0] is True:
                policy_parts[key] = ""
            continue
        if NONCE in value:
            if nonce:
                value = [f"'nonce-{nonce}'" if v == NONCE else v for v in value]
            else:
                # Strip the `NONCE` sentinel value if no nonce is provided.
                value = [v for v in value if v != NONCE]

        value = list(dict.fromkeys(value))  # Deduplicate
        policy_parts[key] = " ".join(value)

    if report_uri:
        report_uri = map(force_str, report_uri)
        policy_parts["report-uri"] = " ".join(report_uri)

    return "; ".join([f"{k} {val}".strip() for k, val in policy_parts.items()])


def _default_attr_mapper(attr_name: str, val: str) -> str:
    if val:
        return f' {attr_name}="{val}"'
    else:
        return ""


def _bool_attr_mapper(attr_name: str, val: bool) -> str:
    # Only return the bare word if the value is truthy
    # ie - defer=False should actually return an empty string
    if val:
        return f" {attr_name}"
    else:
        return ""


def _async_attr_mapper(attr_name: str, val: str | bool) -> str:
    """The `async` attribute works slightly different than the other bool
    attributes. It can be set explicitly to `false` with no surrounding quotes
    according to the spec."""
    if val in [False, "False"]:
        return f" {attr_name}=false"
    elif val:
        return f" {attr_name}"
    else:
        return ""


# Allow per-attribute customization of returned string template
SCRIPT_ATTRS: dict[str, Callable[[str, Any], str]] = {
    "nonce": _default_attr_mapper,
    "id": _default_attr_mapper,
    "src": _default_attr_mapper,
    "type": _default_attr_mapper,
    "async": _async_attr_mapper,
    "defer": _bool_attr_mapper,
    "integrity": _default_attr_mapper,
    "nomodule": _bool_attr_mapper,
}

# Generates an interpolatable string of valid attrs eg - '{nonce}{id}...'
ATTR_FORMAT_STR = "".join([f"{{{a}}}" for a in SCRIPT_ATTRS])


_script_tag_contents_re = re.compile(
    r"""<script        # match the opening script tag
            [\s|\S]*?> # minimally match attrs and spaces in opening script tag
    ([\s|\S]+)         # greedily capture the script tag contents
    </script>          # match the closing script tag
""",
    re.VERBOSE,
)


def _unwrap_script(text: str) -> str:
    """Extract content defined between script tags"""
    matches = re.search(_script_tag_contents_re, text)
    if matches and len(matches.groups()):
        return matches.group(1).strip()

    return text


def build_script_tag(content: str | None = None, **kwargs: Any) -> str:
    data = {}
    # Iterate all possible script attrs instead of kwargs to make
    # interpolation as easy as possible below
    for attr_name, mapper in SCRIPT_ATTRS.items():
        data[attr_name] = mapper(attr_name, kwargs.get(attr_name))

    # Don't render block contents if the script has a 'src' attribute
    c = _unwrap_script(content) if content and not kwargs.get("src") else ""
    attrs = ATTR_FORMAT_STR.format(**data).rstrip()
    return f"<script{attrs}>{c}</script>".strip()
