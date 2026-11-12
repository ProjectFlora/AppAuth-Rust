# Security edge-case audit

Tracking: [#62](https://github.com/ProjectFlora/AppAuth-Rust/issues/62),
[PR #74](https://github.com/ProjectFlora/AppAuth-Rust/pull/74).
Baseline: v0.4.0, `9f061b6`. The remaining native lifecycle and package-consumer
findings are tracked in [#75](https://github.com/ProjectFlora/AppAuth-Rust/issues/75).
This audit covers the declared library boundary; it is not a security
certification or a declaration that all 1.0.0 readiness criteria are complete.

## Coverage ledger

Test names are in `src/authorization.rs` unless another location is given.
The follow-up additions require the latest PR CI run to pass, not just the
initial implementation's run. Final immutable run/commit evidence is maintained
in the [PR verification record](https://github.com/ProjectFlora/AppAuth-Rust/pull/74)
and its [checks](https://github.com/ProjectFlora/AppAuth-Rust/pull/74/checks).

| Audit item | Evidence and decision |
| --- | --- |
| Hostile discovery metadata | Missing/malformed/duplicate known fields, escaped field names, every endpoint URL, exact issuer matching, optional endpoint absence, unknown extensions, 301/302/303/307/308 and no core metadata cache: `discovery_rejects_missing_malformed_and_duplicate_known_fields`, `discovery_validates_every_endpoint_and_exact_issuer`, `discovery_allows_extensions_and_optional_endpoint_absence_for_oauth`, `discovery_rejects_redirect_statuses_and_does_not_cache_metadata` |
| ID Token time boundary | Signed RS256/ES256 tokens at fixed 0/59/60/61-second boundaries for exp/iat/nbf; missing/null required claims, malformed/negative/fractional values, epoch/u64 arithmetic: `src/id_token.rs` time-claim tests |
| JWKS rotation/cache | Changed kid, still-missing kid, transport/HTTP/malformed/empty refresh failures, expiry, independent cancellation, shared concurrent retrieval, repeated/malformed freshness directives and noncacheable responses: `src/id_token.rs` rotation/failure/concurrency/cache tests |
| Callback parameters | Registered components and fixed query values, state mismatch, encoded duplicate names, empty code/error/state, code+error, invalid percent escapes/UTF-8, fragments, valid Unicode/plus/percent values: callback and logout parsing tests; exported native parsing tests in `src/ffi.rs` |
| Token success/error responses | Unique decoded top-level JSON names, success/error conflicts, malformed error values, unknown extensions/codes, exact success status, preserved 429/503 and unchanged refresh state on failure: token/error classification tests |
| Additional authorization/token parameters | All configured reserved names and empty names in builders/refresh maps, encoded endpoint query names and native parameter-vector duplicates. Core tests plus exported authorization/refresh tests in `src/ffi.rs`; Windows .NET package consumer checks reserved and duplicate refresh parameters |
| iOS lifecycle | `IOSAuthorizationFlowSmoke.swift` runs the same adapter with an internal browser-session factory to control completion order. Covers explicit/Task/pre-start cancellation, cancel with and without completion, duplicate and old completions, concurrent-operation rejection, dismissal, start failure, absent payload, generic browser failure, foreign state and reuse. It then runs a real ASWebAuthenticationSession against a mock provider |
| macOS lifecycle | `MacOSAuthorizationFlowSmoke.swift`: partial concurrent connection, unrelated route, independent ephemeral ports, cancellation before/after start, duplicate callback after completion, invalid state and adapter reuse. Exercises actual sockets and a supplied browser-opening closure |
| Android lifecycle | JVM registry tests: contention, duplicate/concurrent delivery, cancellation/re-registration, old cleanup, malformed matching-route routing. `AndroidAuthorizationCallbackActivityTest` adds actual Activity delivery for duplicates, old routes/cleanup and malformed/stale responses rejected by Rust. Existing Custom Tab test covers the full external-browser/callback/code-exchange path on API 34 |
| Windows loopback | Native-target Rust tests: multiple incomplete connections with a valid callback before their timeout, one result from duplicate connections, distinct ports for concurrent operations, independent cancellation, closed sockets/listeners and malformed Host. C++/.NET package consumers load the public DLL/ABI and validate error handling |
| Revocation | Exact HTTP 200 with ignored body (including invalid/already-revoked token), unsupported_token_type, invalid/mixed errors, retryable status, public-client form/hints, reserved endpoint query, malformed inputs, transport cancellation. Core/UniFFI tests plus Windows native/package consumer API checks |
| Native HTTP | Swift copies supplied configuration and disables URLCache; Android sets useCaches=false. Tests prepopulate/observe platform caches and require fresh responses; local HTTP servers verify redirects are not followed and requests can be cancelled |
| Targets/packages | Normal PR CI builds/tests Rust/MSRV, Apple targets and XCFramework, Android Gradle/API 34 instrumentation/AAR/JNI, and Windows MSVC/.NET. The follow-up adds external consumers of the newly built XCFramework, AAR and release DLL/package to the same PR CI |

## Findings fixed in the initial implementation

- Token success responses reject duplicate top-level JSON members and any error
  member. Non-200 responses never issue token values. Valid OAuth error objects
  at 400/401 require a nonempty error code and correctly typed permitted ASCII
  error fields; malformed/ambiguous objects remain HttpStatus errors. Unexpected
  statuses, notably 429/503, retain their status even with OAuth-shaped bodies.
- Authorization/logout callback queries are checked before lossy URL decoding.
  Empty authorization errors, duplicate fixed callback query parameters, and
  reserved token/revocation endpoint query parameters are rejected.
- Time claims use one clock reading after signature verification and JWKS
  retrieval. The JWT dependency still verifies signature/algorithm/issuer/
  audience/required claims; exp/iat/nbf time comparisons are local and
  overflow-safe. The inclusive 60-second policy accepts 59/60 and rejects 61.
- JWKS retrieval is serialized per configuration and its clones. Waiting
  operations recheck and reuse a newly published unexpired snapshot, including
  one still lacking the requested kid. Failures do not replace valid keys;
  expired keys are never a failure fallback. Cancellation releases retrieval
  state independently for waiting and fetching operations.
- Every Cache-Control field is inspected. no-store/no-cache, invalid/repeated
  max-age, invalid/repeated Age, non-text directives, and unsupported
  Expires-only freshness disable caching. Valid max-age minus Age is capped at
  300 seconds. With no freshness policy the existing default remains 300 seconds.
- Windows loopback no longer serially waits for incomplete clients: it permits
  up to 32 concurrent clients with a five-second per-client limit and drains
  active connection tasks on completion/cancellation.
- Malformed matching Android queries/fragments reach core validation instead
  of silently leaving authorization pending. Swift/Kotlin transports bypass
  platform HTTP caches so Rust owns JWKS freshness.

## Follow-up findings and checks (#75)

- **iOS completion/cancellation:** The adapter owns a one-shot browser wait.
  Cancelling resolves it directly, clears browser identity before cancelling
  the OS session, and does not depend on a later OS completion. Browser
  completions are processed on MainActor and matched to the active wait before
  clearing state. Duplicate/old completions cannot resume twice or affect a new
  operation. Public construction still uses ASWebAuthenticationSession; only
  internal tests replace presentation. Deterministic cases and the real browser
  happy path run in the same iOS simulator smoke executable.
- **Native refresh:** Reserved/duplicate names fail without sending or changing
  state; allowed values are form-encoded and omitted refresh tokens are retained.
  Waiting for the authentication-state mutex is now cancellable. A test holds
  the mutex, polls a queued refresh, signals cancellation and requires completion
  before releasing the mutex or sending a request.
- **Activity integration:** Android instrumentation now checks duplicate Activity
  callbacks, cleanup and callbacks from old routes, malformed percent/UTF-8,
  duplicate state and foreign state through the real callback Activity and
  exported Rust callback parser. The registry remains responsible for routing;
  core validation rejects a stale state on a matching route.
- **Current packages:** PR CI invokes the existing consumer fixtures against
  packages built from the PR, rather than treating published v0.4.0 as evidence
  for new code. Apple verifies a Swift executable and iOS simulator library;
  Android installs an external AAR consumer on API 34; Windows builds/runs C++
  and .NET DLL consumers, including reserved/duplicate refresh rejection.
- **Consumer test reliability:** Apple package selection excludes the parallel
  __MACOSX resource-fork directory; the failure was reproduced with a real
  ditto-generated archive. Windows PowerShell checks every native command exit
  code so a failed configure/build/executable cannot appear successful.

## Explicit scope and policy boundaries

- Unknown discovery extensions are ignored. Duplicate unknown members and
  nested opaque extension values are not recursively interpreted/validated.
  Known metadata fields reject duplicate names, including JSON escapes.
- Optional endpoints may be absent/null for OAuth-only configuration. openid
  requests require issuer/JWKS configuration. Discovered endpoints may use a
  different HTTPS host from the issuer. Core discovery has no metadata cache.
- exp/iat are required unsigned integer seconds; nbf is optional, with absent/
  null treated as unspecified. Malformed non-null time values are rejected.
- An unknown kid triggers at most one fetch per validation. Existing-kid
  signature failures do not force a refresh; same-kid replacement is observed
  after expiry. Failures are not negative-cached. No global rate limit/backoff
  is promised. no-store/no-cache results belong only to the retrieving operation,
  so queued operations intentionally perform separate serialized fetches.
- Core callback parsing is stateless; adapters own exactly-once completion and
  resource cleanup. URL comparison uses parsed components and decoded fixed
  query values. Unrelated routes are ignored; a matching route with a stale or
  wrong state terminates the operation, as required by ROADMAP.
- Additional names are case-sensitive. Rust builder calls replace the same
  extension name in their map; native parameter vectors reject duplicates.
  Literal percent signs in caller-supplied names are serialized as literals.
- Revocation HTTP 200 means success with an ignored body under RFC 7009.
  Other 2xx statuses do not confirm revocation. Retry-After is not exposed;
  hosts own retries, overall timeouts, storage encryption and local state deletion.
- Loopback tests cover bounded concurrent clients, not denial-of-service
  resistance after exhausting available connections. Binding port 0 delegates
  collision avoidance to the OS; no fixed-port reservation guarantee is made.
- The internal iOS browser test double checks adapter behavior when callbacks
  arrive, duplicate, disappear or fail; it does not assert control over all OS
  browser process/UI failure modes. The real OS session happy path is tested
  separately. Tests remain mock-provider/simulator/emulator based; real IdP,
  verified production callback domains and real-device compatibility remain
  [explicitly unverified](live-idp-interoperability.md) per ROADMAP.
- PR package consumers verify newly built artifacts, not a future public
  release. Publication checksums, final release downloads and installation
  evidence must be validated for the actual release under the separate 1.0
  distribution readiness criterion. This audit does not publish a release.

## Validation record and closure

- Initial hardening commit `7d4f46a`: [CI run 43211971559](https://github.com/ProjectFlora/AppAuth-Rust/actions/runs/43211971559)
  passed every job: Rust/MSRV/lint/coverage, native Windows Rust/.NET, Apple
  adapters/XCFramework/iOS flow, normal Android Gradle/API 34 instrumentation/
  AAR/JNI. It did not yet include the new external consumers or lifecycle cases.
- Follow-up local checks: Rust 1.99.1 full all-targets/all-features tests
  (100 unit tests, 3 integration tests), warning-free Clippy, iOS simulator
  lifecycle cases and actual ASWebAuthenticationSession flow, all release
  XCFramework slices, static macOS mock flow, and external Swift package consumer.
- Android local Gradle dependency resolution previously failed with repository
  Broken pipe errors. The initial hosted CI normal Gradle pass supersedes the
  supplemental local JVM result. New instrumentation/consumer cases must pass
  hosted CI; the earlier 14-test JVM fallback is not evidence for them.
- Final gate: all latest-commit PR CI jobs, including the new package consumers
  and simulator/emulator cases, must pass. The immutable run/commit link is
  recorded in the PR verification section. Follow-up #75 tracks these findings
  through merge; #62 remains open until the audit is accepted. No 1.0.0-ready
  claim follows merely from a green PR or increased coverage.

## References

- [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252): native-app browser/redirect handling.
- [OIDC Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html) and
  [ID Token validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation).
- [RFC 6749 sections 5.1/5.2](https://www.rfc-editor.org/rfc/rfc6749#section-5.1): token success/error responses.
- [RFC 7009 section 2.2](https://www.rfc-editor.org/rfc/rfc7009#section-2.2): revocation response handling.
