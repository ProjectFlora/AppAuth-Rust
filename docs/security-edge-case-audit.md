# Security edge-case audit

Tracking issue: [#62](https://github.com/ProjectFlora/AppAuth-Rust/issues/62).
Baseline: v0.4.0, commit `9f061b6`. This is an ongoing audit, not a security
certification or a declaration of 1.0.0 readiness.

## Audit ledger

“Partial” means implementation and some tests exist, but the listed gaps remain.
Test names below are in `src/authorization.rs` unless another file is named.

| Area | Existing evidence | Status and remaining work |
| --- | --- | --- |
| Discovery | Existing discovery tests plus `discovery_rejects_missing_malformed_and_duplicate_known_fields`, `discovery_validates_every_endpoint_and_exact_issuer`, `discovery_allows_extensions_and_optional_endpoint_absence_for_oauth`, `discovery_rejects_redirect_statuses_and_does_not_cache_metadata` | Rust parsing/validation covered; native transport redirect/cache checks recorded in the platform increment |
| ID Token time claims | `src/id_token.rs`: `time_claims_allow_exactly_sixty_seconds_of_clock_skew`, `time_claims_reject_missing_required_and_malformed_values`, `time_claim_arithmetic_does_not_overflow`, existing signature/claim rejection tests | Covered for this audit: RS256/ES256 signed tokens with fixed-clock 0/59/60/61-second boundaries; missing required claims, malformed values and overflow-safe arithmetic |
| JWKS rotation | `src/id_token.rs`: existing rotation test plus `failed_refresh_preserves_valid_cache_and_allows_later_retry`, `expired_cache_is_not_used_when_retrieval_fails`, `concurrent_cold_loads_and_rotations_fetch_only_once`, cancellation and cache-directive tests | Rust core covered; native transports now bypass HTTP caches (see platform increment); complete target CI pending |
| Authorization callback | Existing callback tests plus `callback_rejects_empty_duplicate_and_malformed_parameters`, `callback_requires_registered_components_and_fixed_query`, logout encoding test; `src/ffi.rs`: `native_callback_uses_core_encoding_and_session_validation` | Core parsing covered for this increment; adapter lifecycle/operation completion tests pending |
| Token success response | `token_response_rejects_duplicate_members_and_success_error_conflicts`, `token_response_preserves_nested_extension_values`, `token_request_rejects_ambiguous_success_response` | Hardened in this change: reject duplicate top-level decoded names and any error member in an HTTP success response; preserve nested extension values |
| Token error response | Existing error tests plus shared token/revocation duplicate/conflict and status-classification tests, `rejected_token_error_responses_preserve_refresh_state` | Core parsing/status policy covered in this increment; malformed or ambiguous error objects remain HTTP errors |
| Additional request parameters | `all_reserved_names_are_rejected_in_builders_and_authorization_endpoint_query`, `reserved_token_endpoint_queries_fail_before_network_and_preserve_refresh_state`, `refresh_rejects_every_reserved_extra_name_without_changing_state`; `src/ffi.rs`: native reserved/duplicate parameter test | Authorization/token builders, refresh maps, endpoint queries and native authorization vectors covered; native refresh API and platform-specific wrappers remain pending |
| Apple callback lifecycle | Expanded `MacOSAuthorizationFlowSmoke.swift` and Apple adapter SDK checks | macOS partial connections, independent ports, listener cancellation/duplicate rejection and invalid-state reuse checked locally; iOS runtime cancellation/duplicate/session-race cases remain pending |
| Android callback lifecycle | Expanded `AndroidRedirectSelectorTest`, existing activity/browser instrumentation tests | Registry contention, duplicate/concurrent delivery, old cleanup, cancellation/re-registration and malformed matching callback routing covered in JVM tests; activity/browser lifecycle races require emulator verification |
| Windows loopback | `src/windows.rs`: stalled connection test tightened; new independent-operation and duplicate-connection tests plus existing malformed Host/cancellation tests | Core handler now concurrent and tested on macOS with actual loopback sockets; native Windows target, system browser and wrappers still require CI |
| Revocation | Existing request/error tests plus success-body/status, public-client form/hints, query/input rejection and cancellation tests; `src/ffi.rs`: native revocation status/error and pre-send validation tests | Rust/UniFFI behavior covered in this increment; Windows native wrapper execution and complete package CI remain pending |
| Native HTTP caching/redirects | Apple native transport exercised against expanded macOS mock provider; Android transport JVM tests with ResponseCache and local HTTP server | Both supplied transports bypass platform caches; redirect checks pass locally. Android AGP/emulator and Apple device validation remain pending |
| Target/package CI | `.github/workflows/ci.yml`, `release-consumer.yml`, `release.yml` | Pending: record successful runs against the final audited commit for every declared target and package |

## Decisions for this increment

- Token success responses must be JSON objects with unique top-level member
  names, including extension names. Compare decoded names so JSON escapes do
  not bypass duplicate detection. Do not include response values in errors.
- Reject an `error` member in an HTTP success response, including null or an
  otherwise invalid error value. This is a local hardening policy for ambiguous
  success responses. Non-success HTTP handling was initially unchanged; the token-error/revocation increment below records its subsequent hardening.
- Nested extension values remain opaque JSON; recursive duplicate rejection is
  outside this increment. No provider-specific interpretation is added.
- Discovery metadata is not cached by the Rust core. Audit JWKS cache policy
  separately from native HTTP cache behavior.
- Keep the ROADMAP lifecycle contract: unrelated redirects are ignored;
  a matching redirect with wrong state terminates the active operation.
  A stale callback using the same redirect must be tested against that contract.

## Time-claim audit increment

- Production validation reads system time once, after signature verification and
  any JWKS retrieval. Tests inject a fixed Unix timestamp through a private
  clock callback; the public Rust and FFI interfaces are unchanged.
- Signature, algorithm, issuer, audience and required-claim checks remain with
  `jsonwebtoken`. Its wall-clock exp/nbf checks are disabled in favor of local
  validation of exp, iat and optional nbf against that single clock reading.
- Accept exp up to and including 60 seconds in the past; accept iat and nbf up
  to and including 60 seconds in the future. Reject a 61-second deviation.
  This preserves the existing inclusive 60-second policy.
- exp and iat must be unsigned integer seconds and are required. nbf is optional;
  absent or null nbf is treated as unspecified. A present non-null nbf must be
  unsigned integer seconds. Malformed nbf values are now rejected rather than
  relying on the dependency's permissive optional-claim parsing.
- Signed-token tests use both supported algorithms for the skew boundaries.
  Additional cases cover required-claim absence/null, invalid JSON types,
  negative/fractional numbers, the Unix epoch and u64 arithmetic limits.
- Validation evidence: Rust 1.99.1 local
  `cargo test --locked --workspace --all-targets --all-features` passed
  (64 unit tests and 3 integration tests); `cargo test --locked --doc` passed
  (1 doc-test). `cargo fmt --check` and `git diff --check` also passed.
  Native OS and release-package CI evidence remains pending in the ledger above.

## JWKS audit increment

- Each configuration and its clones share an asynchronous retrieval lock.
  Cold-cache and unknown-kid operations recheck the cache after waiting and
  reuse a newly published, unexpired snapshot, even if it still lacks the kid.
  The retrieval lock prevents older overlapping requests from overwriting a
  newer snapshot. Unrelated configurations do not share the lock.
- An unknown kid triggers at most one fetch per validation. A fresh set lacking
  the requested key rejects the token. Signature failure for an existing kid
  does not trigger a fetch; same-kid key replacement is observed after expiry.
- Failed HTTP/transport retrieval, malformed JSON, and empty JWKS reject the
  requesting token without replacing the cache. An unexpired previous set can
  still validate its own keys; an expired set is never a fallback. Later
  operations may retry. Fetch failures are not cached or shared as results.
- Waiting operations have independent cancellation. Cancelling a waiter leaves
  the active fetch running; cancelling/dropping the fetching operation releases
  the lock so another operation can retry. Even a custom transport that ignores
  the cancellation handle is dropped when core cancellation is signalled.
- Every Cache-Control field is inspected. no-store and no-cache disable reuse;
  valid max-age is capped at 300 seconds after subtracting Age. Invalid or
  repeated max-age, invalid/repeated Age, and non-text Cache-Control disable
  caching. Expires without max-age also disables caching rather than attempting
  unsupported HTTP date-based freshness calculations. Without an explicit
  freshness policy, the existing default of 300 seconds remains.
- No-store/no-cache results are usable only for the retrieving validation and
  are not retained for waiting operations. They therefore intentionally require
  separate serialized retrievals. There is no negative-key cache, retry backoff,
  or global rate limit; later independent unknown-kid validations may fetch
  again. These controls are outside this increment, not implied guarantees.
- Tests deterministically hold/release transport requests to cover concurrent
  cold loads and rotations, including still-missing kid, cloned configurations,
  cancellation and recovery. Other tests cover refresh failures, expired keys,
  noncacheable responses, and malformed/duplicate freshness directives.
- Validation evidence: Rust 1.99.1 local
  `cargo test --locked --workspace --all-targets --all-features` passed
  (73 unit tests and 3 integration tests); `cargo test --locked --doc` passed
  (1 doc-test). Formatting and diff whitespace checks passed.
- Native HTTP cache behavior and complete target/package CI remain pending;
  this change only guarantees caching of responses delivered to the Rust core.

## Discovery, callback and reserved-parameter increment

- Discovery tests reject missing required fields, invalid field types, duplicate
  known fields (including JSON-escaped names), unsafe URLs for every supported
  endpoint, issuer differences, and HTTP 301/302/303/307/308 responses. Existing
  default transport tests separately verify that redirects are not followed.
- Unknown metadata extensions are ignored without interpretation. Duplicate
  unknown extension members are not rejected by the typed deserializer; they
  do not affect known fields. This increment covers duplicates of consumed
  metadata fields, not recursive validation of opaque extension objects.
- Missing/null optional endpoints remain allowed for OAuth-only configuration;
  requesting openid without jwks_uri fails before browser launch. Endpoints
  may use a different HTTPS host from the issuer. There is no core discovery
  cache: a test verifies that a second call fetches updated metadata even after
  an earlier response advertised a long cache lifetime.
- Authorization and logout callbacks reject malformed percent escapes and
  invalid UTF-8 before the URL library can silently replace bytes. Empty
  authorization error values are invalid responses. Tests also cover empty
  code/state, missing response fields, encoded duplicate state, duplicate
  extension parameters, code/error conflicts, registered URL components,
  fixed query values, fragments and valid encoded Unicode/plus/percent values.
- Configured callback URIs reject duplicate fixed query parameters and malformed
  query encoding before browser launch. Callback comparison still operates on
  parsed URL components and decoded query values, not original URL spelling.
- Token endpoint queries now reject every reserved token parameter, including
  percent-encoded names, before transport execution for code exchange and
  refresh. Refresh failure leaves authentication state intact. Non-reserved
  query parameters remain allowed and are retained.
- Tests cover every configured authorization/token reserved name and empty
  names in core builders, every token reserved name in additional refresh maps,
  and reserved/duplicate names through the exported native authorization API.
  Names are case-sensitive. Caller-supplied percent signs are encoded literally.
  Repeated non-reserved builder calls replace the value in Rust's map; duplicate
  entries in native parameter vectors are rejected rather than collapsed.
- Raw core callback parsing does not consume a session. Exactly-once completion,
  duplicate callback delivery, stale operations and listener cleanup remain
  adapter lifecycle responsibilities to be audited next.

Validation for this increment: Rust 1.99.1
`cargo test --locked --workspace --all-targets --all-features` passed
(85 unit tests and 3 integration tests); `cargo test --locked --doc` passed
(1 doc-test). Formatting and diff whitespace checks also passed. These are
local Rust/FFI checks, not native device or release-package CI validation.

## Token-error and revocation increment

- Token issuance and revocation require HTTP 200 for success. Revocation ignores
  the 200 response body, including malformed JSON or error-shaped content, as
  specified by RFC 7009 section 2.2; an invalid/already-revoked token is also a
  successful outcome. Other 2xx responses no longer imply success.
- Valid OAuth error objects on HTTP 400/401 produce AuthorizationServer errors.
  They require a unique top-level JSON object, a nonempty string error code,
  and string-valued optional error_description/error_uri with the RFC 6749
  permitted ASCII characters. Unknown error codes and opaque extensions remain
  allowed; error_uri is neither followed nor exposed as executable content.
- Duplicated decoded keys, malformed optional fields, and coexistence with any
  recognized token success field (even null) are not interpreted as an OAuth
  error. The operation fails with its original HttpStatus. No token values are
  accepted from a non-200 response and failed refreshes retain their state.
- Unexpected statuses, including 403, 429, 5xx and redirects, remain HttpStatus
  regardless of body. In particular 503 cannot be masked by an error-shaped
  body. This is a deliberate stricter classification than the baseline, which
  parsed OAuth errors at any non-2xx status. The API does not expose Retry-After
  or retry automatically; hosts own retry/delay policy.
- Revocation queries reject token, token_type_hint and client authentication
  fields before sending, including encoded names. Tests verify public-client
  forms, special-character encoding, access/refresh/absent hints, empty-input
  rejection, optional unknown native hint rejection and retained non-reserved
  endpoint query values.
- Code exchange and revocation share cancellable form transport dispatch.
  Cancellation wins before dispatch when already signalled and drops in-flight
  work even for custom transports that ignore the cancellation handle.
- Native UniFFI tests check success, unsupported_token_type, malformed errors,
  503 classification and pre-cancelled/invalid-hint requests. Native platform
  wrapper execution and release-package validation remain separate pending work.

Validation for the token-error/revocation increment: Rust 1.99.1
`cargo test --locked --workspace --all-targets --all-features` passed
(95 unit tests and 3 integration tests); `cargo test --locked --doc` passed
(1 doc-test). Formatting and diff whitespace checks passed. Windows wrapper
execution and native platform/package CI remain pending.

## Platform lifecycle and native transport increment

- Windows loopback accepts up to 32 concurrent clients with a five-second
  per-client read/response limit. Completion or cancellation aborts and drains
  connection tasks before returning. Socket read/write failures from unrelated
  clients do not end authorization. Tests require a valid callback to finish
  within two seconds while three partial requests remain open, and verify
  duplicate connections yield one result, active sockets close, independent
  operations receive distinct ports and cancellation does not affect peers.
  There is still no implicit overall authorization timeout or denial-of-service
  guarantee once the concurrent-client limit is exhausted.
- macOS listener start now rejects a stopped/cancelled operation. Expanded
  native smoke checks exercise an open partial socket alongside a valid request,
  independent ephemeral ports, cancellation before start, duplicate callback
  rejection after completion, invalid-state callbacks and adapter reuse after
  failure. Network requests in the listener test have bounded test timeouts.
- iOS checks cancellation before browser startup and guards the queued browser
  cancellation with operation identity, avoiding an old cancellation task
  cancelling a newer session. Both iOS and macOS adapters pass SDK type-checks.
  The new iOS race guard has not been exercised in a simulator/browser race
  harness; duplicate system completion and dismissal/cancellation runtime
  coverage remain pending, not declared out of scope.
- Android callback routing now matches the target without parsing its query or
  fragment. A malformed query/fragment on the matching route reaches Rust and
  terminates with an invalid response, rather than silently leaving the
  operation pending. Core/FFI tests separately verify that rejection. Registry
  tests cover concurrent registration, duplicate and concurrent callbacks,
  cancellation and re-registration, old cleanup after a new registration, and
  unrelated old routes. Same-route stale state is intentionally delivered to
  core validation and is terminal per ROADMAP.
- Swift copies the supplied session configuration, disables URLCache and uses
  reloadIgnoringLocalCacheData. Android sets useCaches=false. The Rust JWKS
  cache is the only caching layer in these supplied transports. Apple native
  tests preload a cache, request twice, verify distinct server responses and
  verify an HTTP redirect target is never requested. Android tests verify its
  ResponseCache is neither read nor written and retain redirect/cancel tests.
- Local validation: `scripts/check-apple-adapters.sh` passed, including pinned
  UniFFI binding regeneration, Swift formatting, iOS 18/macOS 15 SDK type-checks
  and the expanded macOS executable smoke test. This exercises HTTP with a
  local mock and a supplied browser-opening closure, not real IdP/browser UI.
- Normal Android `testDebugUnitTest` could not resolve AGP 8.11.1 due repository
  transport failures (`java.net.SocketException: Broken pipe`). Supplemental
  direct JVM compilation uses Kotlin 2.2.20, generated UniFFI bindings, pinned
  JNA 5.12.0/coroutines 1.10.2/browser 1.8.0/JUnit 4.13.2 dependencies and the
  locally available Android 36.1 android.jar. It compiles all main and unit-test
  Kotlin sources and runs both unit-test classes (14 tests passed). This does not validate AGP,
  the declared compileSdk 35, AAR packaging, JNI on Android or instrumentation.
- Remaining platform work: iOS runtime races, Android activity/browser lifecycle
  instrumentation, native Windows execution and complete target/package CI.

Validation for the platform increment: Rust 1.99.1
`cargo test --locked --workspace --all-targets --all-features` passed
(97 unit tests and 3 integration tests); `cargo test --locked --doc` passed
(1 doc-test). Rust/Swift/Kotlin formatting and diff whitespace checks passed.
Native and supplemental JVM results and their limitations are recorded above.

## PR preparation recheck

- Retried the ordinary Android `testDebugUnitTest --info` task on the same
  branch. Dependency/plugin resolution still failed before compilation or tests
  with repository `java.net.SocketException: Broken pipe` errors for AGP 8.11.1.
  A retry with IPv4 preference and TLS 1.2 also failed during resolution. These
  runs are not evidence of either passing or failing Android tests.
- Rust 1.99.1 `cargo clippy --locked --workspace --all-targets --all-features --
  -D warnings` passed. Previously recorded full Rust, Apple and supplemental JVM
  checks remain the local verification baseline.
- Open a draft PR to run the existing GitHub-hosted Android job: normal Gradle
  unit tests, API 34 emulator instrumentation and release AAR/JNI checks. Keep
  #62 open until remaining audit and final target/package evidence is recorded.

## Sequence and closure

1. Record the baseline and harden ambiguous token success responses (this change).
2. Add deterministic time-claim boundary coverage (covered in this increment).
3. Audit JWKS refresh failure/concurrency and cache directives (core coverage and native cache bypass checks recorded above; full platform CI pending).
4. Complete discovery, callback and reserved-parameter cases in the Rust core (covered for the cases and limits recorded in this increment).
5. Complete platform lifecycle audit cases (local progress and remaining runtime/CI gaps recorded above); revocation Rust/UniFFI cases covered.
6. Record final CI and package evidence, link follow-up issues for gaps, and
   reconcile ROADMAP readiness. This ledger alone does not close #62.

Open gaps above are local tracking entries; follow-up GitHub issues have not
been created yet. A gap must ultimately have a passing test or an explicit,
justified scope decision and a linked follow-up where required by #62.

## References

- [RFC 6749 sections 5.1 and 5.2](https://www.rfc-editor.org/rfc/rfc6749#section-5.1): token success/error responses.
- [OIDC Core ID Token validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation).
- [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252): native-app redirect handling.
- [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009): revocation.
