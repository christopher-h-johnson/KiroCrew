---
title: MCP-app media delivery — stop asking redaction to prove a negative about an opaque blob
status: draft
revision: v1
author: Kiro
created: 2026-09-10
last-audited: 2026-10-04
audited-at: 595ad420c
doc-pr: 10038
implementation-prs: []
tracking-issues:
  - "https://github.com/kirodotdev/KiroCrew/issues/9935"
supersedes: []
superseded-by: []
---

# RFC: MCP-app media delivery — stop asking redaction to prove a negative about an opaque blob

- Status: draft. Nothing implemented. A previous attempt to fix
  [#9935](https://github.com/kirodotdev/KiroCrew/issues/9935) inside the
  redaction layer was blocked three times, each time for a different reason, and
  §4 records why that layer cannot hold the decision at all. This document asks
  maintainers **one yes/no question** (§6): build Option B's per-call media path,
  or descope.
- Author: Kiro
- Created: 2026-09-10
- Audited against: `595ad420c` (2026-10-04)
- Related: [`../system-specs/modules/security.md`](../system-specs/modules/security.md)
  (the redaction passes and the sink registry),
  [`../system-specs/modules/mcp-apps.md`](../system-specs/modules/mcp-apps.md)
  (the render and callback path this touches),
  [`../architecture/mcp.md`](../architecture/mcp.md),
  and [`rfc-app-sandbox-isolation.md`](rfc-app-sandbox-isolation.md) (apps still
  run with full privileges; the trust question here is a narrower instance of the
  same gap).
- Related unmerged work: draft PR
  [#9937](https://github.com/kirodotdev/KiroCrew/pull/9937)
  (`fix/media-data-uri-redaction`) is the redaction-layer attempt this document
  argues against, kept open as a draft so §4's three rejected bounds and their review
  verdicts stay readable. It is deliberately **not** an implementation of this RFC:
  neither remaining answer uses it. It is listed here rather than under
  `implementation-prs` for that reason.

## 1. Summary

An MCP app that returns an inline `data:image/*;base64,…` in its tool payload
renders a broken image. The gateway's redaction passes scan every string leaf of
the payload, a base64 media body is structurally indistinguishable from an
encoded secret, so the credential pass splices a `[REDACTED: credential]` tag
into the body ([#9935](https://github.com/kirodotdev/KiroCrew/issues/9935)).

The obvious fix — exempt inline media from the passes — cannot be justified at
the redaction layer, because every available justification either names a control
that does not cover the actual exfiltration channel (§4.1) or requires proving
that an opaque compressed blob contains no secret, which is not decidable (§4.2,
§4.3). The redaction passes stay media-unaware under every answer here.

Two facts bound what the payload scan defends. The app's own `html` crosses
unredacted in the same frame (§5.2), so a server that *means* to put a credential
in front of its app does not need the payload fields to do it. And the gateway
hands the tool result to the agent harness unredacted, `structuredContent`
included (§5.1). On kiro-cli 2.27.1, the default backend (`ACP_BACKEND_KIRO`), the
model does **not** receive that `structuredContent`: a sentinel placed only there
never reached the model's reply in 11 measured runs, and kiro-cli's own tool report
drops the field (§5.1). That matches the MCP Apps spec. The other selectable
harnesses were not measured.

So for a credential that leaks *during a call*, such as a token in an upstream
error a server echoes into its result, the app-path scan is the only control on the
default backend. `html` is the static shell and cannot carry it, and the model never
sees `structuredContent`. Delivering server-authored fields unredacted would expose
that token to the iframe and to the CSP origins it may connect to, with nothing
offsetting it. That option was considered and is rejected on the measurement (§11).

What remains is one decision (§6): **yes**, build a separate per-call media path
that delivers media bytes as produced while every payload field stays scanned
(Option B), or **no**, descope and record that an MCP app payload cannot carry
inline base64 media (§11). Neither answer depends on what any other harness does
with `structuredContent`, so leaving those harnesses unmeasured does not block it.

## 2. Goals and non-goals

**Goals.**

- G1. An MCP app can deliver per-call media that renders, whatever the container
  format, however it is compressed, and whatever the app declares in its CSP. The
  descope leaves G1 unmet by design.
- G2. No security control is narrowed on the strength of a claim the code does not
  support, and nothing retained is described as protecting more than it does.
  Whatever is delivered unscanned is delivered unscanned *by a stated rule*,
  recorded where an operator reads posture, not by a content heuristic.
- G3. The redaction passes stay media-unaware, and every existing direct caller
  keeps scanning inline media in full.
- G4. Settle one question so the next reviewer reads a decision instead of
  re-deriving it.

**Non-goals.**

- N1. Making a payload safe against a **malicious** MCP server. It authors the
  app, its HTML, its CSP metadata and its `inputSchema`; nothing at this layer
  changes that.
- N2. Reducing what an app can send to its own server. The `tools/call` relay
  (§4.1) is untouched.
- N3. App sandboxing or privilege reduction —
  [`rfc-app-sandbox-isolation.md`](rfc-app-sandbox-isolation.md).
- N4. Streaming parity. A media URI split across chunk boundaries is still scanned
  by a media-unaware `StreamRedactor`; same defect class, different surface, its
  own change.
- N5. Designing Option B's media path here. This RFC asks whether to build one;
  §7 names the constraints its design must meet, and §11 records why the plain
  out-of-band HTTP variant does not meet them.

## 3. The defect

`mcp_apps_render._redact_leaves` applies the credential and exfiltration-URL
passes to every string leaf of `structured_content`, `tool_input` and
`result_content` before the `mcp_app_render` frame is sent
(`src/kiro_crew/mcp_apps_render.py`). Both passes are media-unaware. A webp body
routinely contains an `eyJ`-anchored run or a 40+ character base64 run, so the
heuristics match it and substitute a tag. What reaches the app:

```html
<img src="data:image/webp;base64,[REDACTED: credential]" alt="…">
```

The server's output was correct; the payload is altered in transit. Every MCP app
delivering an inline image is affected, and the platform *invites* one:
`buildMcpAppCsp` (`website/src/lib/mcpAppSrcdoc.ts`) grants the iframe
`img-src 'self' data:` and `font-src 'self' data:`.

Narrowing the matcher is not available: the base64 character class is deliberately
broad, and narrowing it reopens the chunking bypass `_B64_CHUNK_RE` /
`_BARE_SECRET_RUN_RE` are pinned against.

## 4. Why a redaction-layer exemption cannot be justified

This section is the reason the RFC exists. Three bounds were proposed and each
was rejected on review; recording them prevents a fourth attempt at the same
layer. Each is stated as the claim it made and the code that falsifies it.

All three are readable rather than described from memory: they were built and reviewed
on draft PR [#9937](https://github.com/kirodotdev/KiroCrew/pull/9937)
(`fix/media-data-uri-redaction`), whose diff carries the mask/restore machinery, the
container-signature table and the whole-body scan, and whose review thread carries the
verdicts. It is left open as a draft for that record. It is **not** a reference
implementation of anything this document proposes — it implements the approach §4 argues
against, and neither answer in §6 uses any of it.

### 4.1 "It renders in a sandboxed iframe with `connect-src 'none'`, so it cannot egress"

False. An MCP app reaches its own MCP server through a relay that no CSP
directive governs:

- `website/src/components/McpAppFrame.tsx` — the frame `fetch`es
  `POST /api/mcp-apps/call`.
- `api_mcp_apps_call` (`dashboard/handlers/mcp_apps.py`, routed in
  `dashboard/server.py`) — the dashboard relays it to the gateway over the
  uid-gated socket.
- `handle_app_call` (`mcp_gateway/app_call.py`) — the gateway forwards
  `{"name": tool_name, "arguments": arguments}` to the server, where `arguments`
  is iframe-controlled (its own comment says so outright) and validated against
  an `inputSchema` **that same server authored**.

And the payload is handed to app JS in full before any of that: `McpAppFrame.tsx`
holds `payload.tool_input` / `payload.result_content` in `toolInputRef` and
`resultContentRef`, then delivers them over the `ui/notifications/tool-input` and
`ui/notifications/tool-result` notifications.

So `connect-src 'none'` does not mean "cannot exfiltrate". A CSP gate limits
direct CSP-governed egress only, and is never a licence for an exemption.

### 4.2 "The decoded head matches a container signature, so it is a real image"

Insufficient. A structurally valid PNG carries arbitrary bytes in `tEXt`, `zTXt`,
`iTXt`, `COM` or EXIF chunks. Any MCP server can produce a file whose first 12
bytes are a genuine signature and whose metadata carries a credential.

### 4.3 "Decode the whole body and scan the decoded bytes"

Insufficient, and not completable. Scanning decoded bytes does catch an ASCII
secret in a metadata chunk, but it misses anything the scanner cannot see as
text:

- **Compressed sections.** PNG `IDAT` is deflate; a compressed credential reads
  as binary noise.
- **Formats stdlib cannot decompress.** stdlib has `zlib` only. Pillow is in the
  runtime (`install_requires` in `setup.cfg` carries `pdfplumber` and
  `qrcode[pil]`, both of which pull it), and it can decode gif, jpeg and webp to
  raw pixels. That narrows the table below without closing it: a scan of decoded
  pixel bytes still misses a credential that is *visible* in the image rather than
  encoded in its bytes, which is the pixel case below. Nothing in
  `install_requires` carries brotli, so woff2 stays opaque either way:

  | Format | Compression | Scannable with stdlib |
  |---|---|---|
  | bmp, ttf, otf | none | already fully scanned |
  | png, woff | zlib/deflate | yes |
  | gif | LZW | no |
  | jpeg | Huffman + DCT | no |
  | **webp** | VP8/VP8L | **no** |
  | avif, heic | AV1/HEVC | no |
  | woff2 | brotli | no |

  #9935 is a `data:image/webp`, so with stdlib alone "decompress or refuse to
  exempt" leaves the reported defect unfixed, and decoding it with Pillow only
  moves it into the pixel case.
- **Pixels.** The most ordinary way a credential ends up inside an image is a
  screenshot of a token on screen. That secret survives full decompression and is
  invisible to any byte-level scan; detecting it needs OCR.

The general shape: an exemption at this layer requires proving a negative about
an opaque blob. Adding a fourth bound would be the review smell
[`AGENTS.md`](../../AGENTS.md) already names — when a review finds "X also
reaches the fence via spelling Y", the question is whether the **subject** is
wrong.

## 5. What the payload scan defends

Two facts in the code bound it, and they cover different cases. §5.2 covers a
server that means to leak. §5.1 asks whether anything besides the iframe receives
an accidental per-call leak, and on the default backend the measured answer is
that the model does not.

### 5.1 The harness receives the identical bytes, unredacted; on kiro-cli the model does not

The gateway returns the tool result to the agent harness as
`append_marker(result, spool_id)`: `_fetch_and_deliver_ui` reads
`structuredContent` into the spool, sets the response's `result` to
`append_marker(result, spool_id)` and hands it to the harness with
`_deliver_to_stub`. `append_marker` prepends the render marker to the first
**text** content item and copies everything else through, so `structuredContent`
reaches the selected harness's MCP client exactly as the server wrote it.
`test/test_mcp_gateway_apps_spool.py` and `test/test_mcp_apps_e2e.py` both assert
the delivered `result` still carries the server's `structuredContent`. The gateway
performs no redaction on that path: every `redact` call in `mcp_gateway/backend.py`
feeds a **log line** (the spawn command in `spawn_backend`, a stderr line in
`_pump_stderr`, the failed-tool-call breadcrumb built by `_tool_call_error_text` and
the identifiers `_log_safe_identifier` cleans for it, and the declared-temp refusal
warning), never the response.

Inside this repository the trace stops there. Nothing in `src/kiro_crew/acp/` reads
`structuredContent`. Crew's own record of a tool result comes from the harness's ACP
`tool_call_update`, which `_build_tool_result_event` joins, redacts and head-cuts at
`session_directive.MAX_TOOL_RESULT_CHARS`; for an ordinary MCP envelope
`_mcp_content_text` keeps only `content[].text`. That record is the harness's report
to Crew, not the model's context, so whether the model sees `structuredContent` had
to be measured.

**Measured on kiro-cli.** On 2026-10-04, kiro-cli 2.27.1, the default backend
(`ACP_BACKEND_KIRO`), was driven over ACP with model routing left at `auto`, through
a throwaway workspace agent whose only tools were one stdio probe MCP server. The
probe's `probe_lookup` returns a fresh random sentinel **only** in
`structuredContent`, beside the neutral text "Lookup finished." in `content`; a
second tool, `probe_control`, returns a different sentinel inside its `content` text
as the control. The prompt asked the agent to call both, then repeat verbatim every
identifier, field and value each returned, including any structured data. The probe
mounts on kiro-cli directly rather than through Crew's gateway; that is the same
input, because `append_marker` changes only `content` and passes `structuredContent`
through, as the two tests above pin.

| Variant | `structuredContent` sentinel in the model's reply | control sentinel in the reply |
|---|---|---|
| plain MCP tool | 0 of 3 | 3 of 3 |
| MCP App tool (`_meta.ui.resourceUri` on the definition and the result) | 0 of 5 | 5 of 5 |
| plain MCP tool with an `outputSchema` | 0 of 3 | 3 of 3 |

In every run the model said `probe_lookup` returned plain text only. kiro-cli's own
`tool_call_update` `rawOutput` for that tool holds the `content` items and no
`structuredContent` key, so the sentinel appears in no ACP frame at all, and Crew's
replayed record of the result is "Lookup finished." because kiro-cli never put the
field on the wire, not because `_mcp_content_text` dropped it. In the app variant
kiro-cli did not advertise the `io.modelcontextprotocol/ui` extension in its MCP
`initialize` and never sent `resources/read`, so it did not fetch the `ui://`
resource either. Two runs are recorded as replayable fixtures:
`test/fixtures/acp_frames/kiro/structured-content-plain-live.jsonl` and
`test/fixtures/acp_frames/kiro/structured-content-app-live.jsonl`, each with its
`.expected.json` and a `_meta.note` that specifies the probe server and the driver,
which are not in the repository.

What this does and does not show. The evidence is the model's reply plus kiro-cli's
own report, not kiro-cli's outbound model request, which was not inspected; the two
agree, and the control shows the model repeats what it was given. A result whose
`content` is empty, leaving `structuredContent` as the only payload, was not tested;
the #9935 shape carries both, and that is what was measured. The result matches the
MCP Apps extension spec (stable
[2026-01-26](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx)),
which treats `content` as the text for model context and `structuredContent` as UI
data a host should not add to it; [ext-apps#380](https://github.com/modelcontextprotocol/ext-apps/issues/380)
records that some hosts do anyway. The other selectable harnesses (`ACP_BACKEND_CLAUDE`,
`ACP_BACKEND_KAS`, `ACP_BACKEND_CODEX`, `ACP_BACKEND_OPENCODE`, `ACP_BACKEND_PI`,
`ACP_BACKEND_GOOSE`, `ACP_BACKEND_DEEPSEEK`) were not measured; the same capture
applies to each. §6 does not need them.

So for one tool result, the server's `structuredContent` goes to two places:

| Destination | Path | Redacted? |
|---|---|---|
| the selected harness's MCP client | gateway → `append_marker` → harness | **no** |
| the model, on kiro-cli 2.27.1 | not forwarded by kiro-cli (measured above) | n/a |
| the app | spool → `handle_tool_result` → owner WS → iframe | yes |

On the default backend, then, the app-path scan is the only control between an
accidental per-call leak in `structured_content` and every recipient that can carry
it further. The price it charges is the corrupted image in §3.

### 5.2 The app's own HTML crosses unredacted beside it

In the same `mcp_app_render` frame that carries the three redacted payload fields,
`mcp_apps_render.handle_tool_result` sends:

```python
"html": data.get("html", ""),          # server-authored, NOT redacted
...
"structured_content": red_structured,  # redacted
"tool_input": red_input,               # redacted
"result_content": red_result,          # redacted
```

The document the iframe actually executes — authored by the same MCP server —
crosses with no redaction. A server that wants a credential inside its own app
does not need a compressed PNG; it can write one into `html`.

That fact reaches only a server that **means** to leak. `html` is the app's static
shell, the `ui://` resource the gateway reads beside the call, and per-call data
cannot live there (§11). So a credential that leaks *during* a call, such as a
token in an upstream error the server echoes into `result_content`, is never in
`html`. For that accidental case unscanned `html` proves nothing, and the payload
scan is the only thing between the token and the iframe.

### 5.3 What follows

- **A server that means to leak** is not stopped by the payload scan. It can
  already write the credential into `html` (§5.2). Against that server the payload
  fields are not a boundary.
- **An accidental per-call leak** is stopped by it. `html` cannot carry the token,
  and on kiro-cli the model never receives `structuredContent` (§5.1), so the scan
  keeps the token out of the iframe and out of reach of the network connections
  `_redact_leaves`' own docstring says the iframe can open to its declared CSP
  origins. On the default backend that is every recipient.

That is why the payload fields stay scanned under both answers in §6, and why
every attempt to exempt media by content inspection failed: the exemption has to
prove a negative about an opaque blob (§4), inside a field that is a real boundary
for the accidental case.

| Field | Authored by | Does the receiving server already hold it raw? | Does scanning the app's copy protect anyone? |
|---|---|---|---|
| `html` | the MCP server | it wrote it | not scanned at all today |
| `structured_content`, `result_content` | the MCP server | it wrote it; the harness holds an unredacted copy via `append_marker`, and on kiro-cli the model does not (§5.1) | **not against a server that means to leak** (§5.2). Against an accidental per-call leak, yes: on the default backend it keeps the token from every recipient, the iframe and its declared CSP origins included |
| `tool_input` | the **model** | **yes** — it is the `params.arguments` of the `tools/call` the server executed, forwarded unscrubbed (§5.4) | **no, against the server.** Only against the browser-side surface |

### 5.4 `tool_input` is different in origin, but not in exposure to the server

`tool_input` is the one field the receiving server did not **author**: it is
`_PendingRequest.tool_arguments`, captured from `params.arguments` in
`mcp_gateway/backend.py`, so its content came from the model's context and may carry
a credential the model picked up from another server, a file read or the user's
environment.

That is a difference in provenance, not in what the server can see. Those arguments
are the ones the gateway forwarded so the tool could execute, and nothing scrubs them
on the way out: `secret_uri.py` resolves `secret://` in environment values at spawn,
`rewriter.py` rewrites agent JSON, and neither touches call arguments. So redacting
the render-frame copy withholds nothing from the server or from an app that server
authored. What the scan still does is keep the value out of the **browser-side**
surface — the iframe DOM, and anything with reach into the page. Both answers in §6
keep it, and whether it should exist at all is recorded as Q6.

## 6. The decision this RFC asks for

One yes/no: **build Option B's per-call media path (yes), or descope (no).**

This choice is the **entry condition for any implementation** (§8). It is not made by
merging this document, and not made by the defaults in §12. Until then the shipped
behaviour stands, #9935 stays open, and apps that inline media stay broken.

Neither answer depends on what a harness does with `structuredContent`. Both keep all
three payload fields scanned on the way to the iframe, and neither touches the
harness-bound result, so whatever an unmeasured harness does with that field is
today's behaviour under either answer and is not changed by this decision. That is
why the unmeasured harnesses in §5.1 do not block it. The third answer earlier
revisions offered, delivering server-authored fields unredacted, is rejected on the
kiro-cli measurement (§11); because it would be one rule across every harness,
failing on the default backend is enough, and measuring the others could not revive
it.

**Who records it, and where.** [GOVERNANCE.md](../../GOVERNANCE.md): maintainers decide,
in public, on the pull request the decision belongs to, and where they disagree a
majority decides. No separate forum, meeting or vote exists or is needed here. So the
answer is a comment on **this document's own PR** answering yes (Option B) or no (the
descope), from any reviewing maintainer, cross-posted to
[#9935](https://github.com/kirodotdev/KiroCrew/issues/9935) because that is where the
affected app authors are watching. When it lands, the answer goes into this document's
front matter — `status: accepted` plus the answer — so it survives after the thread
scrolls away.

**If nobody answers.** Governance sets no deadlines and this RFC invents none. But a
stall is not neutral, so the fallback deliberately needs no maintainer action: the
descope in §11 is an ordinary documentation change, falls outside GOVERNANCE.md's scope
test for needing an RFC at all, and can be proposed directly — close #9935 as "an MCP app
payload cannot carry inline base64 media" and say so in
[mcp-apps](../system-specs/modules/mcp-apps.md), recording that the only in-spec route
left is a remote URL under `csp.resourceDomains`, with the caveats §11 measures. The
app's `ui://` resource is not that route: it is the static shell and cannot carry
per-call media (§11).

### Yes — Option B: close the boundary, and build a media path

- Redact `html` too, and keep redacting all three payload fields.
- Inline media in the payload stays unexpressible, so media needs a path that does
  not exist today: a **separate** media resource the gateway fetches and serves as
  bytes. Note what this is not — the app's existing `ui://` resource is its static
  shell, and per-call media cannot live there (§11), so "just use a `ui://` resource"
  is not available as advice. This is a new mechanism to build, not a redirect to one.
- #9935 is then resolved by that mechanism plus a migration, not by an exemption —
  and not by documentation alone.

Honest cost. Redacting `html` will corrupt app markup the same way it corrupts a
base64 body (an app's inline `<script>` with a long token-shaped constant is
indistinguishable from a secret), so this needs its own answer to the same false
positive one layer up, and it can break apps that render correctly today. Apps that
inline media stay broken until they move to the new path. It is the larger answer,
because the media path has to be designed and built first. And the media path
delivers per-call, server-authored opaque bytes to the iframe **unscanned**, because
§4 rules out scanning them: a token inside an image (a metadata chunk, or a
screenshot of it) reaches the iframe and, through the connections `_redact_leaves`'
docstring says it can open, the CSP origins the app declares, which need not be the
server's own. Today those bytes arrive mangled by the scan rather than inspected, so
this is new exposure confined to media bytes. Option B narrows the accidental-leak
exposure to that class, and the text fields stay scanned, but it does not close it.

### No — descope

The descope keeps every scan and every behaviour as shipped, and records that an MCP
app payload cannot carry inline base64 media. It adds no exposure. Its costs are in
§11: G1 stays unmet, and the only in-spec route left pushes app authors toward
widening their own CSP.

This RFC makes no recommendation between the two. Both are coherent; the current
state, an invited inline image that is silently corrupted, is neither.

## 7. What each answer changes

Nothing in `src/kiro_crew/security/` under either answer. The passes stay
media-unaware, no `data:`/`blob:` pattern is added, and no new facade entry point
exists.

- **Yes (Option B).** The media resource is a new mechanism needing its own design,
  and it must meet the constraints §11 measures: the iframe is a null-origin
  `srcdoc` document with no `allow-same-origin`, so `img-src 'self'` does not match
  the dashboard origin, and a design that widens every app's CSP to reach the bytes
  spends the property this path exists to keep. The `security_posture`
  redaction-sink row for `mcp_apps_render.py` then records that `html` and all three
  payload fields are scanned, and that the media path delivers media bytes unscanned
  to the iframe and its declared CSP origins, by rule (G2). The registry test that
  requires a partially covered sink to disclose it applies to that row.
- **No (descope).** One docs change in
  [mcp-apps](../system-specs/modules/mcp-apps.md) recording the limit and the
  `resourceDomains` route with §11's caveats, and #9935 closed with the reason in §6.

## 8. Migration plan

**Nothing is unblocked.** No work begins until §6 is explicitly answered, as a comment
on this document's PR and reflected in its front matter (`status: accepted`) — not
inferred from a default and not inferred from this RFC being merged. Merging the RFC
records the *question and the analysis*; it does not select an answer.

**No default in §12 authorizes shipping a behaviour change.** The defaults say what this
document assumes while it is being read, not what may proceed if nobody replies.

### If the answer is yes (Option B)

- **Phase 1 — the media path.** Design and build the separate per-call media resource
  §7 describes, additively: no existing field changes and no app stops rendering.
  Exit criteria: the bytes of a `data:image/webp` body served through the path reach
  the iframe byte-identical, asserted with an app whose `csp` declares `connectDomains`
  so the answer does not depend on the app's CSP; no app's CSP is widened to reach
  it; `git diff main -- src/kiro_crew/security/` is empty; and the posture row states
  that media bytes on this path are unscanned.
- **Phase 2 — close `html`.** `html` passes through the redaction passes, with an
  answer to the markup false positive above, and apps that inline media get a
  migration note pointing at the Phase 1 path. Exit criteria: a test asserts `html`
  and `structured_content` are treated alike, so a later change cannot start scanning
  one without the other, and the posture row records the split.

### If the answer is no (descope)

One documentation PR, as §7 describes. The RFC then moves to `implemented`.

## 9. Backward compatibility

- **Under the descope** nothing changes: the wire format, the spool records and every
  behaviour stay as shipped, and apps that inline media stay broken.
- **Under Option B** compatibility breaks deliberately. Phase 1 is additive. Phase 2
  redacts `html`, which can corrupt markup that renders today, and apps inlining media
  must move to the new path, which is why Phase 2 carries a migration note. What the
  media path adds to the wire is part of its design and is not fixed here.

## 10. Security considerations

Stated so nobody reads more into it than it claims.

- Neither answer removes the scan from any payload field, so neither adds the
  accidental-leak exposure §5.3 describes for text fields. Under Option B the media
  path delivers server-authored per-call media bytes to the iframe unscanned, and from
  there to the CSP origins the app declares; §6 states that cost.
- Neither answer changes the harness-bound result, so what a harness does with
  `structuredContent` is today's behaviour under both. On kiro-cli it does not reach
  the model (§5.1); the other selectable harnesses are unmeasured.
- It does not reduce what an app can send to its own server. The `tools/call`
  relay in §4.1 stays exactly as it is.
- It does not isolate apps. That is
  [`rfc-app-sandbox-isolation.md`](rfc-app-sandbox-isolation.md).
- It does not make the payload safe against a **malicious** MCP server. Nothing
  at this layer can: the server authors the app, its HTML, its CSP metadata and
  its `inputSchema`.
- It does not address the streaming surface, where a media URI split across chunk
  boundaries is scanned by a media-unaware `StreamRedactor`. That is the same
  defect class on a different surface and deserves its own change.

## 11. Alternatives considered

- **Deliver server-authored fields unredacted (Option A in earlier revisions).** Keep
  the scan on `tool_input` only, and deliver `structured_content` and
  `result_content` as produced, so media needs no exemption. Its only argument for an
  accidental per-call leak was that the model already received the same bytes
  unredacted, so the app-path scan was not what contained the token. On kiro-cli
  2.27.1, the default backend, the model does not receive `structuredContent` (§5.1),
  so that argument fails and the option would expose such a token to the iframe and
  its declared CSP origins with nothing offsetting it. Rejected.
- **Exempt media after a content scan.** §4. Rejected: not decidable.
- **Serve media out of band over HTTP.** Extract media at spool time, store the
  bytes as a sidecar, and serve them from a new authenticated endpoint. Rejected
  as the design for two reasons: the iframe is a null-origin `srcdoc` document with
  no `allow-same-origin`, so `img-src 'self'` does not match the dashboard origin
  and the CSP would have to be widened for every app; and it does not change the
  trust question, since the bytes still reach the same app. Option B's media path
  has to meet the first constraint, not inherit this design.
- **Remote media via `resourceDomains`.** An app can declare
  `csp.resourceDomains: ["https://cdn.example"]`, which `buildMcpAppCsp` folds into
  `img-src 'self' data: https://cdn.example` (the same list also widens
  `font-src`, `media-src`, `script-src` and `style-src` — it cannot be scoped to
  images), and serve `<img src="https://cdn.example/…">` instead of inlining.
  `sanitizeCspDomain` accepts only `https://[*.]host[:port]` with no path, and
  silently drops anything else, so a malformed entry fails closed to `'self'
  data:` with no error explaining why.

  **This does not solve the defect; it relocates it.** The exfiltration scan flags
  the payload, not the destination — `scan_exfiltration_urls`'s own contract is that
  "fixed credentials and the base64/length heuristics inspect the URL path+query
  regardless of host" — so declaring a domain buys no exemption from redaction. Measured against the passes on this tree, an ordinary CDN image URL
  can be corrupted exactly the way an inline body is:

  | Image URL shape | Result |
  |---|---|
  | unsigned, short query, e.g. `…/2026-09-03/<uuid>.png` | survives |
  | Cloudinary-style transforms in the **path** | survives |
  | content-addressed filename (base64url of a digest) | `…cdn.example.[REDACTED: credential].png` — the credential pass matches the base64 run and mangles host and path together |
  | imgix-style transform chain (public params only) | `[REDACTED: suspicious URL to cdn.example.net]` — crosses `_EXFIL_QUERY_MIN_LEN` on length alone |
  | signed URL (`X-Amz-Signature`, or CloudFront `Signature`+`Key-Pair-Id`) | replaced with the same exfil tag |

  So the surviving set is unsigned, short-query, non-content-addressed paths, which
  excludes private and expiring media outright, and an app author has no way to
  learn that boundary short of reading `exfil.py`. The only exemption is
  operator-level (`_exfil_exempt_hosts`, companion-supplied exact hosts, and it
  waives only the base64/length heuristics — fixed credential patterns still
  apply), so an app author cannot fix this for themselves. Rejected as a remedy: it
  spends a real sandbox property — a null-origin frame that issues no outbound
  subresource requests at all — on a defect it does not remove.

- **Descope — accept the broken image.** The "no" answer in §6, and the fallback if
  nobody answers. **Not cheap, and not neutral**, on two counts that its obvious
  phrasing hides. First, "use a `ui://` resource instead" has no landing place: that
  resource is the app's static shell, while media in the reported case is per-call
  data arriving over `ui/notifications/tool-input` / `tool-result`, so there is no
  in-spec home for it there. Second, the only in-spec alternative left is the
  `resourceDomains` path above — which means declining to fix this would push
  affected app authors into widening their own CSP, trading the null-origin,
  no-outbound-request property for browser-direct egress the gateway never sees, and
  still leaves them exposed to the same false positive. A descope should be chosen
  knowing it makes app authors weaken their own sandbox to work around a control
  that, per §5.3, is a real boundary only for the accidental leak.
- **Narrow the credential matcher.** Rejected: reopens the chunking bypass.

## 12. Open questions

Each carries a default so the decision request is answerable rather than open-ended.
A default records what this document assumes while it is being read; **none of them
authorizes an implementation to proceed.** The §6 answer is what gates any work, and it
has to be made explicitly (§8). Numbers are kept stable; withdrawn questions stay as
stubs.

1. **Q1 — is the `html` asymmetry intended or an oversight?** §5.2 rests on it, and it
   bears only on Option B's `html` half: a server that means to leak, not an accidental
   per-call leak, which never reaches `html`. Answering §6 "yes" treats it as an
   oversight, since Option B redacts `html`. Default if unanswered: treat it as
   intended, because it has been the shipped behaviour and redacting `html` corrupts
   app markup the same way it corrupts a base64 body.
2. **Q2 — does the payload reach the model?** Measured on kiro-cli 2.27.1, the default
   backend: it does not (§5.1, with the fixtures under `test/fixtures/acp_frames/kiro/`).
   The other selectable harnesses are unmeasured, and §6 does not depend on them.
   Whether such a path would be intended is moot while no answer in §6 rests on it.
3. **Q3 — does `structured_content` ever carry model-authored data?** Withdrawn with
   the option §11 rejects first.
4. **Q4 — should `tool_input` be exempt for media too?** Withdrawn with the same
   option.
5. **Q5 — streaming parity** (N4) — separate change, or a prerequisite? Default if
   unanswered: separate, because the batch path is what #9935 reports.
6. **Q6 — should `tool_input` be scanned at all, given §5.4?** The server already
   holds those arguments raw, so the scan withholds nothing from the server or from
   an app that server authored; its only remaining effect is keeping the value out of
   the browser-side surface. Three consistent answers: (a) keep it, as both answers in
   §6 do, accepting that the benefit is narrower than "model-authored data is
   protected"; (b) drop it, on the grounds that it is no boundary against the
   server, which leaves the sink row an honest "not scanned" for that field; (c) keep it and additionally scrub outbound
   `params.arguments` at the gateway, which is the only option that would actually
   withhold a model-held credential from the server — a much larger change, and not
   one this document proposes. Default if unanswered: **(a)**, because it is the
   conservative side and because (b) and (c) both change behaviour for every MCP
   server rather than for the render path this RFC is scoped to.

## Note on citation style

The "Writing a new RFC" section of [README.md](README.md) asks for `file:line`
citations. `scripts/docs_lint.py` **fails** on line citations in prose and asks for
a symbol name instead, on the grounds that a name survives the refactor that moves
a line. The gate is enforced, so this document cites symbols and names the commit
it was measured at (`595ad420c`). Worth reconciling the two.
