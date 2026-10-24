# Validation Report — Device-Code Phishing Bench for ScamIntel

**Ran:** 2026-10-24T04:15:49Z (final regression; rounds run 2026-10-24 UTC)
**Module under test:** `device_code_detect.py` v1.2.0 (sha256: `b33e5bd23023d25f…`)
**Baseline compared:** `email-phish-takedown-2.4.0.py` (sha256: `348bd88e36a01025…`)
**Bench:** `bench/fixture_gen.py` (sha256: `ef85ba9e69a72884…`), `bench/bench.py` (sha256: `43bcb912cebecfcd…`)
**Result: 65/65 attack fixtures caught, 0/7 control false positives.**
Machine-readable detail: `bench/results-final.json` (per-fixture verdicts,
scores, findings, stock signals); `bench/results-round3.json` is the final
mutation round's full-set run, `bench/results.json` a fresh re-run of the
same set.

Every fixture is synthetic and defanged: fake codes, fictional `.example`
sender domains, inert 1×1 image stand-ins, hand-rolled minimal PDFs. No live
phishing infrastructure was touched, no real inboxes, accounts, or credentials
were used. Real endpoint *strings* (e.g. `microsoft.com/devicelogin`) appear
only as inert text inside local files — that is the point of the technique
under test: the URL is legitimate, the code is the weapon.

## Why this bench exists

Device-code phishing (EvilTokens-style PhaaS kits; Jalisco-toolkit fresh-code
flows) does not rely on a malicious URL. The victim is handed an
attacker-supplied code and walked to the **real** `microsoft.com/devicelogin`.
URL scoring therefore has nothing to bite on. Measured confirmation from this
bench: composed through its own static functions (`header_analysis`,
`analyze_html`, `analyze_url`/`score_url`, `providers`), stock 2.4.0 flagged
**0 of 65** attack fixtures. (Fair framing: 2.4.0 has no device-code verdict
concept at all — it would still surface the URLs as IOCs in a case file. The
bench ran the static path only, network collection off.)

## Patterns tested, by name

| Family | Fixtures | Caught |
|---|---|---|
| EvilTokens classic (HTML + plain, "sign-in assistance", M365 branding) | 5 | 5/5 |
| aka.ms shortlink to real devicelogin | 1 (+mutations) | all |
| Jalisco fresh-code (send-time code, 15-min TTL) | 1 | 1/1 |
| Jalisco thread code-refresh (3 messages, rotating codes) | 3 | 3/3 |
| QR-relay (payload only inside an image) | 1 (+mutations) | all |
| Teams meeting verification pretext | 1 | 1/1 |
| Zoom meeting verification pretext | 1 | 1/1 |
| IT help-desk impersonation, lookalike company domain | 1 | 1/1 |
| Code split across subject + body | 1 (+mutations) | all |
| Lure in .html attachment | 1 (+mutations) | all |
| Lure in .pdf text layer | 1 | 1/1 |
| Non-English lure (Spanish; mutations add DE/FR) | 1 (+mutations) | all |
| Lookalike device-login domain (vs. genuine endpoint) | 1 (+mutations) | all |
| Obfuscated endpoint text (`microsoft[.]com`, wrapped, zero-width, spaced dots) | 1 (+mutations) | all |
| No-urgency / implied-instruction minimal lures | 2 (+mutations) | all |
| Seeded mutations (code formats × endpoint forms × pretexts × placements × languages) | 46 | 46/46 |
| **Total attack** | **65** | **65/65** |

Benign controls (7): genuine Microsoft sign-in alert, bank OTP, GitHub device
verification, Zoom invite — all scored 0. Three controls land in the
human-review tier **by design**: legitimate IT device enrollment (45 —
endpoint + instructions, but no supplied code and a consistent sender),
legitimate MFA-setup QR mail (50 — QR construction, consistent sender), and a
security-awareness newsletter quoting a lure (70, verdict capped at
suspicious by the awareness-context rule). None reached the lure verdict.

## Rounds

- **Round 0** (19 attack / 6 control canonical fixtures): module v1.0.0 caught
  17/19, 1 control FP. Three breaks (below) → hardened to v1.1.0/v1.2.0.
- **Round 1** (14 mutations): one new miss class (below) → hardened. 33/33.
- **Round 2** (14 mutations, new seed): no new miss classes. 47/47.
- **Round 3** (18 mutations, new seed): no new miss classes. 65/65.
- Stopping rule met: ≥3 rounds and two consecutive rounds with no new miss
  classes. All earlier fixtures remain in `bench/fixtures/` as regression
  cases; the final run re-executes the full set.

## What broke, and the fix for each

1. **`r0-code-split` — split code not reassembled (score 70, verdict stalled
   at suspicious).** The lure gate required a detected code; the code existed
   only as a subject fragment (`…KX7Q-`) plus a body fragment. Fix: the module
   now reassembles subject-fragment + body-fragment into a full code
   candidate and records a `code_split_subject_body` finding. Fixture is a
   permanent regression case; mutation rounds generated further split
   variants (e.g. `r3-mut-16`, caught at 65 — the closest call in the bench).
2. **`r0-qr-lure` — QR-relay payload invisible to text analysis (score 50).**
   Code and endpoint live inside the image by design. Fix in two steps:
   (a) QR-construction findings (`qr_only_body` + `qr_verification_framing`)
   were made verdict-establishing, not merely additive; (b) round 1 then
   produced the harder variant **`r1-mut-06`** — a QR lure with *no* brand
   impersonation in the mail (voicemail pretext) — which exposed that the
   framing bonus was brand-gated. Fix: framing is now scored on the
   construction itself (image-only payload + "scan to verify your sign-in"),
   plus a `lure_attachment_name` signal for victim-facing filenames
   (`sign-in-qr.png`). `r1-mut-06` now scores 80.
3. **`r0-ctl-newsletter` — false positive on security-awareness reporting
   (score 70 → lure).** An article *about* the technique quotes the endpoint,
   an example code, and the instruction language. Fix: an awareness-context
   rule — when ≥2 reporting-framing patterns are present **and** there is no
   brand-claim/sender mismatch and no lookalike infrastructure, the verdict
   is capped at `device-code-suspicious` (human review) regardless of score.
   The dampener never touches mismatch or lookalike signals, so an
   impersonating lure cannot talk its way under the cap with boilerplate
   alone unless it also gives up impersonation.

## How the module decides (summary)

Weighted indicators, no network calls: legitimate device-login endpoint
referenced (25) / shortlink endpoint (15) / lookalike endpoint (45);
attacker-supplied code, context-checked (30; 18 without context);
entry instructions (20); brand-claim vs. sender-domain mismatch (15) or
lookalike sender domain (25); TTL urgency (10); QR-only body (15) +
QR sign-in framing (35); lure in attachment (+10) and lure-named attachment
(+10); thread code-refresh (15); split-code reassembly (+5). Verdict
`device-code-lure` at score ≥ 60 with a lure-establishing finding (code,
lookalike endpoint, or QR framing); 35–59 is `device-code-suspicious`.
Classes are reported separately: `legitimate-endpoint-abuse`,
`lookalike-endpoint`, `qr-relay`, `attachment-borne`.

## Honest limitations of this validation

1. **Not independent:** the same author wrote the detector, the templates,
   and the mutations. Fixtures are modeled on public TTP descriptions of
   EvilTokens/Jalisco patterns, not on captured live kits. Reproducible
   (fixtures + per-fixture results are in the package), but not a second
   pair of eyes.
2. **No OCR:** QR image contents are never decoded (the bench's images are
   inert stand-ins). QR detection rests on construction, framing text, and
   attachment naming. A QR lure with a neutral filename, no brand claim, and
   >140 characters of innocuous body text would land at suspicious at best.
3. **Awareness-cap tradeoff:** a lure that copies awareness boilerplate
   *and* avoids brand impersonation and lookalikes could be capped at
   suspicious. Accepted deliberately: the alternative is auto-flagging
   security newsletters, and suspicious still routes to a human.
4. **Code-shape assumption:** code detection targets 8–10-character mixed
   alphanumeric codes (the Microsoft device-code shape). Flows using purely
   numeric codes are scored on endpoint + instruction + sender context only.
5. **Thread signal needs thread context:** `thread_code_refresh` fires only
   when the caller passes prior thread messages. Each Jalisco thread fixture
   was also caught standalone, but the refresh weight itself is
   context-dependent.
6. **Language coverage:** instruction/urgency phrases cover EN/ES/DE/FR.
   Other locales fall back to code + endpoint + sender-mismatch signals.
7. **Static path only:** the bench exercises detection, not the network
   collection path; nothing here changes any live configuration.

## Recommendation

Ship `device_code_detect.py` as a companion module in the next release
(2.5.0 candidate), wired the way `fake_captcha_detect` is: optional import,
`analyze_message()` fed from the fields `process_message` already extracts
(headers, bodies, URLs, attachment text), SHA-256 pinned in the case record
via the existing `companion_module_info` pattern. Keep the bench as the
release gate for the module: new lure patterns become fixtures first, and a
release ships only on a clean full-set run. This package is local and
review-ready; nothing was pushed anywhere.
