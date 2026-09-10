"""Media ``data:``/``blob:`` URI carve-out — behaviour.

A widget emits ``<img src="data:image/webp;base64,…">``. The base64 body is a
rendered sub-resource (it never fetches, never egresses — the widget CSP is
``img-src data: blob:`` with a documented "NEVER fetches" contract) but is
structurally identical to an encoded secret, so before this carve-out the
credential and exfil passes spliced a ``[REDACTED: credential]`` tag INTO the
``src`` and stranded the image.

The carve-out is default-deny and surface-scoped. The two bare passes
``redact_credentials`` / ``redact_exfiltration_urls`` carry NO media awareness —
every direct caller scans inline media in full. Only the composed facade helper
``redact_rendered_assistant_text`` masks media around both passes, and only the
dashboard's browser-rendered assistant-text sites (via ``_redact_leaves`` in
``mcp_apps_render.py``) reach it. So the behavioural "survives byte-identical /
is exempt" tests below target the FACADE, while the inverse tests assert the
bare passes still REDACT a media URI.

``_mask_media_data_uris`` (in ``security/redaction.py``) masks such URIs to an
inert placeholder before the passes run and restores them after. The carve-out
lives on the one surface that renders inline media — the backend.

The scope is deliberately MEDIA-ONLY: an ``image/`` or ``font/`` ``data:`` URI
and a ``blob:`` URL are exempt; a ``data:text/…`` blob is still scanned, so it
cannot become a smuggling channel. Widening the MIME scope to ``text``/
``application`` would open exactly that, and these tests fail if it does.
"""

from __future__ import annotations

import re

from kiro_crew.security import (
    _mask_media_data_uris,
    _unmask_media_data_uris,
    redact_credentials,
    redact_exfiltration_urls,
    redact_rendered_assistant_text,
)

# The scope primitives stay OFF the security facade — like ``_MEDIA_DATA_URI_RE``,
# they are imported from their owning module by tests.
from kiro_crew.security.redaction import (
    _MEDIA_DATA_URI_RE,
    _MEDIA_URI_PREFIX_RE,
    _media_head_is_plausible,
)

# A signed JWT — the exact shape the credential pass redacts. Embedding it inside
# a media body proves the mask (not luck) is what leaves the src intact.
_JWS = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"
    ".dQw4w9WgXcQdQw4w9WgXcQdQw4w9WgXcQdQw4w9WgXc"
)

# A long, plausible webp base64 body (no dots, so not a JWT itself) — the 40+
# base64-char run that trips the base64/entropy heuristics.
_WEBP_BODY = "UklGRhIAAABXRUJQVlA4TAYAAAAvAAAAAAfQ//73v/+BiOh/AAA=" + "A" * 80
_WEBP_URI = f"data:image/webp;base64,{_WEBP_BODY}"
_IMG = f'<img src="{_WEBP_URI}" alt="Art Deco Diamond and Emerald Necklace in Platinum">'

# A webp body whose head decodes to the ``RIFF….WEBP`` container signature (so the
# plausibility gate exempts it on the opted-in surface) AND whose tail carries a
# credential shape (a dot-stripped JWS) that the media-UNAWARE bare passes redact.
# ``_WEBP_BODY`` above survives even the STRICT pass "by accident" (it does not
# trip the credential heuristics), so it cannot show the strict-vs-facade
# divergence. This body can: bare pass → redacted, facade →
# byte-identical. ``UklGRhIAAABXRUJQ`` decodes to ``b'RIFF\x12\x00\x00\x00WEBP'``.
_WEBP_HEAD_B64 = "UklGRhIAAABXRUJQ"
_JWS_NO_DOTS = _JWS.replace(".", "")
_CRED_WEBP_BODY = _WEBP_HEAD_B64 + _JWS_NO_DOTS
_CRED_WEBP_BODY += "A" * ((4 - len(_CRED_WEBP_BODY) % 4) % 4)
_CRED_WEBP_URI = f"data:image/webp;base64,{_CRED_WEBP_BODY}"
_CRED_IMG = f'<img src="{_CRED_WEBP_URI}">'

# The same shape for a font media URI: ``d09GMgABAAAA`` decodes to the woff2
# ``wOF2`` signature, and the tail carries the credential shape.
_WOFF2_HEAD_B64 = "d09GMgABAAAA"
_CRED_WOFF2_BODY = _WOFF2_HEAD_B64 + _JWS_NO_DOTS
_CRED_WOFF2_BODY += "A" * ((4 - len(_CRED_WOFF2_BODY) % 4) % 4)
_CRED_WOFF2_URI = f"data:font/woff2;base64,{_CRED_WOFF2_BODY}"


class TestBehaviour:
    """The media URI survives ONLY through the surface-scoped facade.

    The carve-out lives outside the bare passes, so these "survives
    byte-identical / is exempt" assertions target
    ``redact_rendered_assistant_text`` — the one media-aware batch entry point.
    That helper masks the media URI around both passes and restores it
    byte-identical, so the src is untouched. The inverse (a bare pass REDACTS a
    media URI) is pinned in :class:`TestBarePassesAreMediaUnaware`.
    """

    def test_image_data_uri_survives_facade_byte_identical(self) -> None:
        result, warnings = redact_rendered_assistant_text(_IMG)
        assert result == _IMG
        assert warnings == []

    def test_image_body_embedding_a_real_jwt_is_still_protected(self) -> None:
        # The credential-shaped body (a dot-stripped JWS run) would be redacted by
        # the media-unaware passes, corrupting the src. Through the facade the mask
        # (not luck — this body DOES trip the heuristics, unlike ``_WEBP_BODY``)
        # leaves the src byte-identical.
        result, warnings = redact_rendered_assistant_text(_CRED_IMG)
        assert result == _CRED_IMG
        # Sanity: the bare pass proves this body really is redaction-bait.
        bare, bare_warnings = redact_credentials(_CRED_IMG)
        assert bare != _CRED_IMG
        assert bare_warnings

    def test_blob_url_is_exempt_through_the_facade(self) -> None:
        html = '<img src="blob:https://dash.example.test/9f1c-4a2b-babe">'
        # A blob:https URL embeds an http-looking run; the facade must leave it
        # byte-identical through BOTH passes.
        assert redact_rendered_assistant_text(html)[0] == html

    def test_bare_jwt_outside_a_media_uri_is_still_redacted(self) -> None:
        result, warnings = redact_credentials(f"leaked: {_JWS}")
        assert _JWS not in result
        assert warnings

    def test_text_plain_data_uri_is_still_scanned(self) -> None:
        # Media-scoped: a non-media data: URI is NOT exempt, so a secret hidden in
        # a text/plain base64 body must still be redacted — even through the
        # media-aware facade.
        uri = f"data:text/plain;base64,{_JWS}"
        result, _ = redact_rendered_assistant_text(f"note: {uri}")
        assert _JWS not in result

    def test_application_octet_stream_data_uri_is_still_scanned(self) -> None:
        uri = f"data:application/octet-stream;base64,{_JWS}"
        result, _ = redact_rendered_assistant_text(f"blob: {uri}")
        assert _JWS not in result


class TestBarePassesAreMediaUnaware:
    """The inverse of :class:`TestBehaviour`: the bare ``redact_credentials`` /
    ``redact_exfiltration_urls`` carry NO media awareness, so a media URI fed
    DIRECTLY to a bare pass is scanned in full — a credential-shaped body gets a
    redaction tag spliced in.

    Only the facade exempts a media URI; a bare pass never does.
    ``test_text_plain_data_uri_is_still_scanned`` and the octet-stream case above
    cover the media-UNAWARE MIME scope; these add the labelled ``image`` /
    ``font`` media URI cases, which the bare passes redact.
    """

    def test_bare_credential_pass_redacts_a_labelled_image_media_uri(self) -> None:
        # A data:image/webp;base64,<credential-shaped body> fed to the bare
        # credential pass is scanned in full: the body is redacted.
        result, warnings = redact_credentials(_CRED_IMG)
        assert result != _CRED_IMG
        assert _CRED_WEBP_BODY not in result
        assert "[REDACTED: credential]" in result
        assert warnings

    def test_bare_credential_pass_redacts_a_labelled_font_media_uri(self) -> None:
        result, warnings = redact_credentials(f'url("{_CRED_WOFF2_URI}")')
        assert _CRED_WOFF2_BODY not in result
        assert "[REDACTED: credential]" in result
        assert warnings

    def test_bare_exfil_pass_redacts_a_media_uri_carrying_a_suspicious_url(
        self,
    ) -> None:
        # The exfil pass is likewise media-unaware: a media data: URI whose body
        # is not the constraint here — an exfiltration URL adjacent to it is
        # rewritten while the media URI is NOT spared by any carve-out. Feed a
        # data: URI whose surrounding text carries a redaction-worthy secret, and
        # confirm the bare exfil pass does not treat the media URI as exempt.
        exfil = f"https://evil.example/steal?token={_JWS}"
        text = f'{exfil} <img src="{_CRED_WEBP_URI}">'
        result, warnings = redact_exfiltration_urls(text)
        # The exfil pass fires on the suspicious URL (media-unaware: no carve-out
        # short-circuits the scan).
        assert warnings
        assert _JWS not in result


class TestMaskRoundTrip:
    def test_mask_then_unmask_is_identity(self) -> None:
        masked, originals = _mask_media_data_uris(_IMG)
        assert _WEBP_URI not in masked
        assert originals == [_WEBP_URI]
        restored, unmask_warnings = _unmask_media_data_uris(masked, originals)
        assert restored == _IMG
        assert unmask_warnings == []

    def test_placeholder_carries_no_credential_or_base64_shape(self) -> None:
        # The whole point of the placeholder: a pass run between mask and unmask
        # must leave it untouched, or the restore would fail.
        masked, originals = _mask_media_data_uris(_IMG)
        scanned, warnings = redact_credentials(masked)
        assert scanned == masked
        assert warnings == []
        restored, unmask_warnings = _unmask_media_data_uris(scanned, originals)
        assert restored == _IMG
        assert unmask_warnings == []

    def test_multiple_media_uris_are_masked_independently(self) -> None:
        a = "data:image/webp;base64," + "Q" * 60
        b = "data:font/woff2;base64," + "Z" * 60
        html = f'<img src="{a}"> and url({b})'
        assert redact_credentials(html)[0] == html

    def test_no_media_uri_is_a_cheap_noop(self) -> None:
        text = "no media here, just prose"
        masked, originals = _mask_media_data_uris(text)
        assert masked == text
        assert originals == []


class TestBatchHardening:
    """Batch-helper hardening: mask strips injected sentinels, unmask fails
    closed on an unresolved index, duplicate URIs round-trip, and a suspicious
    URL coexists with a media URI through the facade.

    These target the batch helpers and the ``redact_rendered_assistant_text``
    facade directly rather than the media-unaware bare passes.
    """

    def test_injected_placeholder_sentinel_does_not_survive_or_collide(self) -> None:
        # An attacker-supplied \x00media:0\x00 sentinel sits next to a real media
        # URI. The mask strips such a look-alike BEFORE masking, so it never
        # becomes a placeholder and cannot collide with a real placeholder index
        # (which would restore the sentinel into the real URI and leak a raw
        # \x00).
        text = f'\x00media:0\x00 and <img src="{_WEBP_URI}">'

        masked, originals = _mask_media_data_uris(text)
        # The only masked span is the REAL URI; the injected sentinel was stripped.
        assert originals == [_WEBP_URI]
        assert "\x00media:0\x00 " not in masked  # attacker sentinel gone
        assert _WEBP_URI not in masked  # real URI is masked

        restored, warnings = _unmask_media_data_uris(masked, originals)
        # Round-trip preserves the real URI; the raw sentinel is not leaked.
        assert _WEBP_URI in restored
        assert restored == f' and <img src="{_WEBP_URI}">'
        assert "\x00" not in restored
        assert warnings == []

    def test_unresolved_index_fails_closed_to_credential_tag(self) -> None:
        # A placeholder whose index is out of range for the originals list must
        # fail closed to the credential tag, never leak a raw \x00, and surface a
        # COUNT-ONLY warning (no secret bytes, no index value).
        text = "before \x00media:5\x00 after"
        restored, warnings = _unmask_media_data_uris(text, [])

        assert "[REDACTED: credential]" in restored
        assert "\x00" not in restored
        assert warnings  # a warning is surfaced
        # Count-only: the warning text carries neither the raw index nor bytes.
        assert all("5" not in w for w in warnings)
        assert all("\x00" not in w for w in warnings)

    def test_same_media_uri_twice_round_trips(self) -> None:
        # Duplicate-tolerant: the same URI appearing twice is masked to two
        # independent placeholders and both restore correctly.
        text = f'<img src="{_WEBP_URI}"> then again <img src="{_WEBP_URI}">'

        masked, originals = _mask_media_data_uris(text)
        assert originals == [_WEBP_URI, _WEBP_URI]
        assert _WEBP_URI not in masked

        restored, warnings = _unmask_media_data_uris(masked, originals)
        assert restored == text
        assert warnings == []

    def test_suspicious_url_redacted_while_media_uri_survives(self) -> None:
        # Through the facade, an exfiltration-looking URL carrying a real
        # credential is redacted while a valid media URI survives intact, and
        # warnings are surfaced.
        exfil = f"https://evil.example/?data={_JWS}"
        text = f'{exfil} next to <img src="{_WEBP_URI}">'

        result, warnings = redact_rendered_assistant_text(text)

        # The media URI is preserved byte-identical.
        assert _WEBP_URI in result
        # The embedded credential does not survive.
        assert _JWS not in result
        # Warnings are surfaced by the facade.
        assert warnings
        # No raw sentinel leaks.
        assert "\x00" not in result


class TestScopePrimitiveCoupling:
    """Pin ``_MEDIA_URI_PREFIX_RE`` EQUAL in MIME scope to the batch
    ``_MEDIA_DATA_URI_RE`` by reading the shared shape out of each source, so a
    silent widening of one alone fails loudly.

    Same convention as
    ``test_the_two_base64_run_patterns_stay_structurally_coupled``: both patterns
    spell ``data:(?:image|font)/`` LITERALLY rather than sharing a built
    constant, so the MIME alternation is extracted from each ``.pattern`` and
    compared.
    """

    def test_the_two_media_patterns_share_one_mime_alternation(self) -> None:
        # Extract ``data:(?:image|font)/`` from BOTH patterns by source
        # inspection and assert they are equal, so widening the MIME scope of one
        # (adding ``text``/``application``, say) without the other fails here.
        alternation = re.compile(r"data:\(\?:([A-Za-z|]+)\)/")

        batch = alternation.search(_MEDIA_DATA_URI_RE.pattern)
        prefix = alternation.search(_MEDIA_URI_PREFIX_RE.pattern)
        assert batch, "batch _MEDIA_DATA_URI_RE MIME alternation not found"
        assert prefix, "streaming _MEDIA_URI_PREFIX_RE MIME alternation not found"

        assert batch.group(1) == prefix.group(1)
        # And it is exactly the media-only scope, not a widened one.
        assert set(batch.group(1).split("|")) == {"image", "font"}

        # Negative control: a widened alternation must not compare equal.
        widened = _MEDIA_URI_PREFIX_RE.pattern.replace("(?:image|font)", "(?:image|font|text)")
        assert widened != _MEDIA_URI_PREFIX_RE.pattern, "control failed to mutate"
        widened_match = alternation.search(widened)
        assert widened_match and widened_match.group(1) != batch.group(1)


class TestMediaHeadIsPlausible:
    """The plausibility gate accepts a real container head for the declared MIME,
    refuses a mislabelled secret, and refuses ``image/svg+xml`` (absent from the
    allowlist — text, script-capable).
    """

    def test_real_webp_head_passes(self) -> None:
        # RIFF at 0 AND WEBP at 8 — both checks must match for webp.
        head = b"RIFF" + b"\x12\x00\x00\x00" + b"WEBP"
        assert _media_head_is_plausible("image/webp", head) is True

    def test_real_png_head_passes(self) -> None:
        assert _media_head_is_plausible("image/png", b"\x89PNG\r\n\x1a\n") is True

    def test_mislabelled_aws_key_pair_matches_no_signature(self) -> None:
        # The decoded head of a base64'd AWS key pair matches no container
        # signature, so it is refused for ANY claimed media type — the
        # mislabelled-secret case that MUST be redacted rather than exempted.
        aws_secret = (
            b"AKIAIOSFODNN7EXAMPLE wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY "
            b"ghp_0123456789abcdefghijklmnopqrstuvwxyz"
        )
        head = aws_secret[:16]
        for mime in (
            "image/png",
            "image/webp",
            "image/jpeg",
            "image/gif",
            "font/woff2",
        ):
            assert _media_head_is_plausible(mime, head) is False, mime

    def test_svg_is_refused_even_with_xml_head(self) -> None:
        # image/svg+xml is deliberately ABSENT from the allowlist: it is text and
        # script-capable, not a binary container. It is refused even when the
        # head looks XML-ish.
        assert _media_head_is_plausible("image/svg+xml", b"<?xml version=") is False
        assert _media_head_is_plausible("image/svg+xml", b"<svg xmlns=") is False


