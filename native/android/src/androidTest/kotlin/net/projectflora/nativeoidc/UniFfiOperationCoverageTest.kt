package net.projectflora.nativeoidc

import android.net.Uri
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.native_oidc.FfiAuthenticationState
import uniffi.native_oidc.FfiCancellationHandle
import uniffi.native_oidc.FfiEndSessionOptions
import uniffi.native_oidc.FfiException
import uniffi.native_oidc.FfiHttpRequest
import uniffi.native_oidc.FfiHttpResponse
import uniffi.native_oidc.FfiRegistrationOptions
import uniffi.native_oidc.FfiServiceConfiguration
import uniffi.native_oidc.NativeHttpTransport
import uniffi.native_oidc.beginEndSession
import uniffi.native_oidc.registerPublicClient
import uniffi.native_oidc.revoke
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Android-side coverage of the generated UniFFI bindings (issue #164):
 * exercises every operation and the `FfiException` error mapping from Kotlin
 * on an emulator, without any network activity.
 *
 * The scripted transports below replace the real HTTP stack, so the tests
 * pin what the generated API hands back for each operation and each error
 * variant. The test IDs match the Swift counterparts in
 * `SwiftTests/NativeOIDCTests/NativeOIDCTests.swift`.
 *
 * This class lives in `androidTest` (not in the JVM unit tests) because the
 * Rust library is only packaged as a native `jniLibs` entry: instrumented
 * execution is the only place the generated bindings can be exercised from
 * Kotlin. The real HTTP path is covered by
 * `UrlConnectionNativeHttpTransportTest` and the flow tests in this
 * directory.
 */
@RunWith(AndroidJUnit4::class)
class UniFfiOperationCoverageTest {
    // MARK: - Discovery (D)

    @Test
    fun testD1() = runBlocking {
        val transport = ScriptedTransport()
        transport.response =
            Result.success(
                FfiHttpResponse(
                    status = 200.toUShort(),
                    headers = emptyList(),
                    body = DISCOVERY_DOCUMENT.toByteArray(StandardCharsets.UTF_8),
                ),
            )

        val config =
            FfiServiceConfiguration.discover(
                "https://idp.example/",
                transport,
                FfiCancellationHandle(),
            )
        try {
            assertEquals("https://idp.example/", config.issuer())
            assertEquals("https://idp.example/authorize", config.authorizationEndpoint())
            assertEquals("https://idp.example/token", config.tokenEndpoint())
            assertEquals("https://idp.example/revoke", config.revocationEndpoint())
            assertEquals("https://idp.example/.well-known/jwks.json", config.jwksUri())
            // registrationEndpoint and endSessionEndpoint have no getters on
            // the Kotlin API, so verify discovery retained them by running
            // each operation against the discovered configuration and
            // asserting the advertised URL.

            val registrationTransport = ScriptedTransport()
            registrationTransport.response =
                Result.success(
                    FfiHttpResponse(
                        status = 201.toUShort(),
                        headers = emptyList(),
                        body = PUBLIC_CLIENT_RESPONSE.toByteArray(StandardCharsets.UTF_8),
                    ),
                )
            registerPublicClient(
                config,
                FfiRegistrationOptions(
                    redirectUris = listOf("https://app.example/callback"),
                    clientName = null,
                    initialAccessToken = null,
                ),
                registrationTransport,
                FfiCancellationHandle(),
            )
            assertEquals(1, registrationTransport.recordedRequests.size)
            assertEquals(
                "https://idp.example/register",
                registrationTransport.recordedRequests[0].url,
            )

            val endSession = beginEndSession(config, FfiEndSessionOptions("c1", null, null))
            try {
                assertTrue(
                    endSession.endSessionUrl().startsWith("https://idp.example/logout"),
                )
            } finally {
                endSession.close()
            }

            assertEquals(1, transport.recordedRequests.size)
            val request = transport.recordedRequests[0]
            assertEquals("GET", request.method)
            assertEquals(
                "https://idp.example/.well-known/openid-configuration",
                request.url,
            )
            assertTrue(
                request.headers.any {
                    it.name.equals("Accept", ignoreCase = true) &&
                        String(it.value, StandardCharsets.UTF_8) == "application/json"
                },
            )
        } finally {
            config.close()
        }
    }

    @Test
    fun testD2() = runBlocking {
        val transport = ScriptedTransport()
        transport.response =
            Result.success(FfiHttpResponse(404.toUShort(), emptyList(), ByteArray(0)))

        val error =
            expectFfiExceptionAsync {
                FfiServiceConfiguration.discover(
                    "https://idp.example/",
                    transport,
                    FfiCancellationHandle(),
                )
            }
        if (error is FfiException.HttpStatus) {
            assertEquals(404.toUShort(), error.status)
        } else {
            throw AssertionError("D2: expected FfiException.HttpStatus(404), got $error")
        }
    }

    @Test
    fun testD3() = runBlocking {
        val transport = ScriptedTransport()
        transport.response =
            Result.success(
                FfiHttpResponse(
                    status = 200.toUShort(),
                    headers = emptyList(),
                    body = "not json".toByteArray(StandardCharsets.UTF_8),
                ),
            )

        val error =
            expectFfiExceptionAsync {
                FfiServiceConfiguration.discover(
                    "https://idp.example/",
                    transport,
                    FfiCancellationHandle(),
                )
            }
        assertTrue(
            "D3: expected FfiException.InvalidResponse, got $error",
            error is FfiException.InvalidResponse,
        )
    }

    @Test
    fun testD4() = runBlocking {
        val transport = ScriptedTransport()
        transport.response =
            Result.success(
                FfiHttpResponse(
                    status = 200.toUShort(),
                    headers = emptyList(),
                    body =
                        DISCOVERY_ISSUER_MISMATCH
                            .toByteArray(StandardCharsets.UTF_8),
                ),
            )

        val error =
            expectFfiExceptionAsync {
                FfiServiceConfiguration.discover(
                    "https://idp.example/",
                    transport,
                    FfiCancellationHandle(),
                )
            }
        assertTrue(
            "D4: expected FfiException.InvalidResponse, got $error",
            error is FfiException.InvalidResponse,
        )
    }

    @Test
    fun testD5() = runBlocking {
        val transport = ScriptedTransport()
        transport.response =
            Result.success(FfiHttpResponse(200.toUShort(), emptyList(), ByteArray(0)))

        val error =
            expectFfiExceptionAsync {
                FfiServiceConfiguration.discover(
                    "http://idp.example",
                    transport,
                    FfiCancellationHandle(),
                )
            }
        assertTrue(
            "D5: expected FfiException.InvalidRequest, got $error",
            error is FfiException.InvalidRequest,
        )
        // An invalid issuer must be rejected before calling the transport.
        assertEquals(0, transport.recordedRequests.size)
    }

    @Test
    fun testD6() = runBlocking {
        // #164 D6: the transport throws FfiException.InvalidResponse("boom").
        // The variant is not preserved across the transport boundary and
        // becomes TransportFailure carrying the original message.
        val transport = ScriptedTransport()
        transport.response = Result.failure(FfiException.InvalidResponse("boom"))

        val error =
            expectFfiExceptionAsync {
                FfiServiceConfiguration.discover(
                    "https://idp.example/",
                    transport,
                    FfiCancellationHandle(),
                )
            }
        if (error is FfiException.TransportFailure) {
            assertTrue(
                "D6: expected the message to contain 'boom', got ${error.v1}",
                error.v1.contains("boom"),
            )
        } else {
            throw AssertionError(
                "D6: expected FfiException.TransportFailure containing 'boom', got $error"
            )
        }
    }

    @Test
    fun testD7() = runBlocking {
        // #164 D7: a transport that throws an ordinary Kotlin exception (not
        // a FfiException) must surface as TransportFailure carrying the
        // Transport variant's display text, "HTTP transport failed".
        val transport = ScriptedTransport()
        transport.response = Result.failure(IllegalStateException("network exploded"))

        val error =
            expectFfiExceptionAsync {
                FfiServiceConfiguration.discover(
                    "https://idp.example/",
                    transport,
                    FfiCancellationHandle(),
                )
            }
        if (error is FfiException.TransportFailure) {
            assertEquals("HTTP transport failed", error.v1)
        } else {
            throw AssertionError("D7: expected FfiException.TransportFailure, got $error")
        }
    }

    // MARK: - Revocation (R)

    @Test
    fun testR1() = runBlocking {
        val transport = ScriptedTransport()
        transport.response =
            Result.success(
                FfiHttpResponse(
                    status = 200.toUShort(),
                    headers = emptyList(),
                    body = """{"hint":"access_token"}""".toByteArray(StandardCharsets.UTF_8),
                ),
            )

        val config =
            FfiServiceConfiguration(IDP_AUTHORIZE, IDP_TOKEN)
                .withRevocationEndpoint(IDP_REVOKE)
        try {
            revoke(
                configuration = config,
                clientId = "c1",
                token = "t1",
                tokenTypeHint = "access_token",
                transport = transport,
                cancellation = FfiCancellationHandle(),
            )

            assertEquals(1, transport.recordedRequests.size)
            val request = transport.recordedRequests[0]
            assertEquals("POST", request.method)
            assertEquals(IDP_REVOKE, request.url)
            // The complete sorted field set: a renamed, duplicated, or
            // emptied field fails the comparison, while a harmless
            // reordering of the same fields does not.
            assertEquals(
                listOf(
                    listOf("client_id", "c1"),
                    listOf("token", "t1"),
                    listOf("token_type_hint", "access_token"),
                ),
                formFields(request.body),
            )
        } finally {
            config.close()
        }
    }

    @Test
    fun testR2() = runBlocking {
        val transport = ScriptedTransport()
        transport.response =
            Result.success(FfiHttpResponse(200.toUShort(), emptyList(), ByteArray(0)))

        val config =
            FfiServiceConfiguration(IDP_AUTHORIZE, IDP_TOKEN)
                .withRevocationEndpoint(IDP_REVOKE)
        try {
            revoke(
                configuration = config,
                clientId = "c1",
                token = "t1",
                tokenTypeHint = null,
                transport = transport,
                cancellation = FfiCancellationHandle(),
            )

            assertEquals(1, transport.recordedRequests.size)
            val request = transport.recordedRequests[0]
            // The complete sorted field set: without a hint the request must
            // carry only token and client_id, not even an empty
            // token_type_hint.
            assertEquals(
                listOf(listOf("client_id", "c1"), listOf("token", "t1")),
                formFields(request.body),
            )
        } finally {
            config.close()
        }
    }

    @Test
    fun testR3() = runBlocking {
        val transport = ScriptedTransport()
        transport.response =
            Result.success(FfiHttpResponse(200.toUShort(), emptyList(), ByteArray(0)))

        val config =
            FfiServiceConfiguration(IDP_AUTHORIZE, IDP_TOKEN)
                .withRevocationEndpoint(IDP_REVOKE)
        try {
            val error =
                expectFfiExceptionAsync {
                    revoke(
                        configuration = config,
                        clientId = "c1",
                        token = "t1",
                        tokenTypeHint = "id_token",
                        transport = transport,
                        cancellation = FfiCancellationHandle(),
                    )
                }
            assertTrue(
                "R3: expected FfiException.InvalidRequest, got $error",
                error is FfiException.InvalidRequest,
            )
            // An unsupported hint must be rejected before calling the
            // transport.
            assertEquals(0, transport.recordedRequests.size)
        } finally {
            config.close()
        }
    }

    @Test
    fun testR4() = runBlocking {
        val transport = ScriptedTransport()
        transport.response =
            Result.success(FfiHttpResponse(200.toUShort(), emptyList(), ByteArray(0)))

        val config = FfiServiceConfiguration(IDP_AUTHORIZE, IDP_TOKEN)
        try {
            val error =
                expectFfiExceptionAsync {
                    revoke(
                        configuration = config,
                        clientId = "c1",
                        token = "t1",
                        tokenTypeHint = null,
                        transport = transport,
                        cancellation = FfiCancellationHandle(),
                    )
                }
            assertTrue(
                "R4: expected FfiException.InvalidRequest, got $error",
                error is FfiException.InvalidRequest,
            )
            // A missing revocation endpoint must be rejected before calling
            // the transport.
            assertEquals(0, transport.recordedRequests.size)
        } finally {
            config.close()
        }
    }

    @Test
    fun testR5() = runBlocking {
        val transport = ScriptedTransport()
        transport.response =
            Result.success(
                FfiHttpResponse(
                    status = 400.toUShort(),
                    headers = emptyList(),
                    body =
                        """{"error":"unsupported_token_type","error_description":"nope"}"""
                            .toByteArray(StandardCharsets.UTF_8),
                ),
            )

        val config =
            FfiServiceConfiguration(IDP_AUTHORIZE, IDP_TOKEN)
                .withRevocationEndpoint(IDP_REVOKE)
        try {
            val error =
                expectFfiExceptionAsync {
                    revoke(
                        configuration = config,
                        clientId = "c1",
                        token = "t1",
                        tokenTypeHint = null,
                        transport = transport,
                        cancellation = FfiCancellationHandle(),
                    )
                }
            if (error is FfiException.AuthorizationServer) {
                assertEquals("unsupported_token_type", error.code)
                assertEquals("nope", error.description)
            } else {
                throw AssertionError(
                    "R5: expected FfiException.AuthorizationServer, got $error"
                )
            }
        } finally {
            config.close()
        }
    }

    @Test
    fun testR6() = runBlocking {
        val transport = ScriptedTransport()
        transport.response =
            Result.success(
                FfiHttpResponse(
                    status = 503.toUShort(),
                    headers = emptyList(),
                    body =
                        """{"error":"unsupported_token_type","error_description":"nope"}"""
                            .toByteArray(StandardCharsets.UTF_8),
                ),
            )

        val config =
            FfiServiceConfiguration(IDP_AUTHORIZE, IDP_TOKEN)
                .withRevocationEndpoint(IDP_REVOKE)
        try {
            val error =
                expectFfiExceptionAsync {
                    revoke(
                        configuration = config,
                        clientId = "c1",
                        token = "t1",
                        tokenTypeHint = null,
                        transport = transport,
                        cancellation = FfiCancellationHandle(),
                    )
                }
                // A non-400/401 status must not be parsed as an OAuth error
                // body, even when the body looks like one.
            if (error is FfiException.HttpStatus) {
                assertEquals(503.toUShort(), error.status)
            } else {
                throw AssertionError(
                    "R6: expected FfiException.HttpStatus(503), got $error"
                )
            }
        } finally {
            config.close()
        }
    }

    @Test
    fun testR7() = runBlocking {
        val transport = ScriptedTransport()
        transport.response = Result.failure(FfiException.TransportFailure("down"))

        val config =
            FfiServiceConfiguration(IDP_AUTHORIZE, IDP_TOKEN)
                .withRevocationEndpoint(IDP_REVOKE)
        try {
            val error =
                expectFfiExceptionAsync {
                    revoke(
                        configuration = config,
                        clientId = "c1",
                        token = "t1",
                        tokenTypeHint = null,
                        transport = transport,
                        cancellation = FfiCancellationHandle(),
                    )
                }
            if (error is FfiException.TransportFailure) {
                assertTrue(
                    "R7: expected the message to contain 'down', got ${error.v1}",
                    error.v1.contains("down"),
                )
            } else {
                throw AssertionError(
                    "R7: expected FfiException.TransportFailure containing 'down', got $error"
                )
            }
        } finally {
            config.close()
        }
    }

    // MARK: - Registration (G)

    @Test
    fun testG1() = runBlocking {
        val transport = ScriptedTransport()
        transport.response =
            Result.success(
                FfiHttpResponse(
                    status = 201.toUShort(),
                    headers = emptyList(),
                    body = PUBLIC_CLIENT_RESPONSE.toByteArray(StandardCharsets.UTF_8),
                ),
            )

        val config =
            FfiServiceConfiguration(IDP_AUTHORIZE, IDP_TOKEN)
                .withRegistrationEndpoint(IDP_REGISTER)
        try {
            val response =
                registerPublicClient(
                    configuration = config,
                    options =
                        FfiRegistrationOptions(
                            redirectUris = listOf("https://app.example/callback"),
                            clientName = "My App",
                            initialAccessToken = "iat",
                        ),
                    transport = transport,
                    cancellation = FfiCancellationHandle(),
                )
            assertEquals("c1", response.clientId)

            assertEquals(1, transport.recordedRequests.size)
            val request = transport.recordedRequests[0]
            assertEquals("POST", request.method)
            assertEquals(IDP_REGISTER, request.url)
            val body = JSONObject(String(request.body, StandardCharsets.UTF_8))
            val redirectUris = body.getJSONArray("redirect_uris")
            assertEquals(1, redirectUris.length())
            assertEquals("https://app.example/callback", redirectUris.getString(0))
            assertEquals("My App", body.getString("client_name"))
            assertTrue(
                request.headers.any {
                    it.name.equals("Authorization", ignoreCase = true) &&
                        String(it.value, StandardCharsets.UTF_8) == "Bearer iat"
                },
            )
        } finally {
            config.close()
        }
    }

    @Test
    fun testG2() = runBlocking {
        val transport = ScriptedTransport()
        transport.response =
            Result.success(
                FfiHttpResponse(
                    status = 400.toUShort(),
                    headers = emptyList(),
                    body =
                        """{"error":"invalid_redirect_uri","error_description":"bad"}"""
                            .toByteArray(StandardCharsets.UTF_8),
                ),
            )

        val config =
            FfiServiceConfiguration(IDP_AUTHORIZE, IDP_TOKEN)
                .withRegistrationEndpoint(IDP_REGISTER)
        try {
            val error =
                expectFfiExceptionAsync {
                    registerPublicClient(
                        configuration = config,
                        options =
                            FfiRegistrationOptions(
                                redirectUris = listOf("https://app.example/callback"),
                                clientName = "My App",
                                initialAccessToken = null,
                            ),
                        transport = transport,
                        cancellation = FfiCancellationHandle(),
                    )
                }
            // A registration error must map to the registration variant,
            // not the authorization-server variant.
            if (error is FfiException.ClientRegistrationServer) {
                assertEquals("invalid_redirect_uri", error.code)
                assertEquals("bad", error.description)
            } else {
                throw AssertionError(
                    "G2: expected FfiException.ClientRegistrationServer, got $error"
                )
            }
        } finally {
            config.close()
        }
    }

    @Test
    fun testG3() = runBlocking {
        val transport = ScriptedTransport()
        transport.response =
            Result.success(
                FfiHttpResponse(
                    status = 201.toUShort(),
                    headers = emptyList(),
                    body =
                        """{"client_id":"c1","application_type":"native","token_endpoint_auth_method":"none","client_secret":"sec"}"""
                            .toByteArray(StandardCharsets.UTF_8),
                ),
            )

        val config =
            FfiServiceConfiguration(IDP_AUTHORIZE, IDP_TOKEN)
                .withRegistrationEndpoint(IDP_REGISTER)
        try {
            val error =
                expectFfiExceptionAsync {
                    registerPublicClient(
                        configuration = config,
                        options =
                            FfiRegistrationOptions(
                                redirectUris = listOf("https://app.example/callback"),
                                clientName = "My App",
                                initialAccessToken = null,
                            ),
                        transport = transport,
                        cancellation = FfiCancellationHandle(),
                    )
                }
            // A public client registration must never return a client
            // secret.
            assertTrue(
                "G3: expected FfiException.InvalidResponse, got $error",
                error is FfiException.InvalidResponse,
            )
        } finally {
            config.close()
        }
    }

    @Test
    fun testG4() = runBlocking {
        val transport = ScriptedTransport()
        transport.response =
            Result.success(FfiHttpResponse(500.toUShort(), emptyList(), ByteArray(0)))

        val config =
            FfiServiceConfiguration(IDP_AUTHORIZE, IDP_TOKEN)
                .withRegistrationEndpoint(IDP_REGISTER)
        try {
            val error =
                expectFfiExceptionAsync {
                    registerPublicClient(
                        configuration = config,
                        options =
                            FfiRegistrationOptions(
                                redirectUris = listOf("https://app.example/callback"),
                                clientName = "My App",
                                initialAccessToken = null,
                            ),
                        transport = transport,
                        cancellation = FfiCancellationHandle(),
                    )
                }
            if (error is FfiException.HttpStatus) {
                assertEquals(500.toUShort(), error.status)
            } else {
                throw AssertionError(
                    "G4: expected FfiException.HttpStatus(500), got $error"
                )
            }
        } finally {
            config.close()
        }
    }

    @Test
    fun testG5() = runBlocking {
        val transport = ScriptedTransport()
        transport.response =
            Result.success(FfiHttpResponse(201.toUShort(), emptyList(), ByteArray(0)))

        val config = FfiServiceConfiguration(IDP_AUTHORIZE, IDP_TOKEN)
        try {
            val error =
                expectFfiExceptionAsync {
                    registerPublicClient(
                        configuration = config,
                        options =
                            FfiRegistrationOptions(
                                redirectUris = listOf("https://app.example/callback"),
                                clientName = "My App",
                                initialAccessToken = null,
                            ),
                        transport = transport,
                        cancellation = FfiCancellationHandle(),
                    )
                }
            // A missing registration endpoint must be rejected before
            // calling the transport.
            assertTrue(
                "G5: expected FfiException.InvalidRequest, got $error",
                error is FfiException.InvalidRequest,
            )
            assertEquals(0, transport.recordedRequests.size)
        } finally {
            config.close()
        }
    }

    @Test
    fun testG6() = runBlocking {
        // #164 G6: a malformed redirect URI must be rejected before any
        // request is made.
        val transport = ScriptedTransport()
        transport.response =
            Result.success(FfiHttpResponse(201.toUShort(), emptyList(), ByteArray(0)))

        val config =
            FfiServiceConfiguration(IDP_AUTHORIZE, IDP_TOKEN)
                .withRegistrationEndpoint(IDP_REGISTER)
        try {
            val error =
                expectFfiExceptionAsync {
                    registerPublicClient(
                        configuration = config,
                        options =
                            FfiRegistrationOptions(
                                redirectUris = listOf("https://app.example/callback", "not a url"),
                                clientName = null,
                                initialAccessToken = null,
                            ),
                        transport = transport,
                        cancellation = FfiCancellationHandle(),
                    )
                }
            assertTrue(
                "G6: expected FfiException.InvalidRequest, got $error",
                error is FfiException.InvalidRequest,
            )
            // The malformed redirect URI must be rejected before calling the
            // transport.
            assertEquals(0, transport.recordedRequests.size)
        } finally {
            config.close()
        }
    }

    @Test
    fun testG7() = runBlocking {
        // A transport failure while the registration request is in flight is
        // surfaced as TransportFailure carrying the transport's message.
        val transport = ScriptedTransport()
        transport.response = Result.failure(FfiException.TransportFailure("down"))

        val config =
            FfiServiceConfiguration(IDP_AUTHORIZE, IDP_TOKEN)
                .withRegistrationEndpoint(IDP_REGISTER)
        try {
            val error =
                expectFfiExceptionAsync {
                    registerPublicClient(
                        configuration = config,
                        options =
                            FfiRegistrationOptions(
                                redirectUris = listOf("https://app.example/callback"),
                                clientName = null,
                                initialAccessToken = null,
                            ),
                        transport = transport,
                        cancellation = FfiCancellationHandle(),
                    )
                }
            if (error is FfiException.TransportFailure) {
                assertTrue(
                    "G7: expected the message to contain 'down', got ${error.v1}",
                    error.v1.contains("down"),
                )
            } else {
                throw AssertionError(
                    "G7: expected FfiException.TransportFailure containing 'down', got $error"
                )
            }
            assertEquals(1, transport.recordedRequests.size)
        } finally {
            config.close()
        }
    }

    // MARK: - End Session (E)

    @Test
    fun testE1() {
        val config =
            FfiServiceConfiguration(IDP_AUTHORIZE, IDP_TOKEN)
                .withEndSessionEndpoint(IDP_LOGOUT)
        try {
            val session =
                beginEndSession(
                    config,
                    FfiEndSessionOptions(
                        clientId = "c1",
                        idTokenHint = "id_token",
                        postLogoutRedirectUri = "com.example.app:/logout",
                    ),
                )
            try {
                val url = session.endSessionUrl()
                // Compare the exact query fields: substring matching would
                // accept client_id=c10 or id_token_hint=id_token_extra.
                val uri = Uri.parse(url)
                assertEquals(4, uri.queryParameterNames.size)
                assertEquals("c1", uri.getQueryParameter("client_id"))
                assertEquals("id_token", uri.getQueryParameter("id_token_hint"))
                assertEquals(
                    "com.example.app:/logout",
                    uri.getQueryParameter("post_logout_redirect_uri"),
                )
                // The session must carry the generated state.
                val state = uri.getQueryParameter("state")
                assertNotNull(
                    "E1: end-session URL must carry the generated state",
                    state,
                )

                val redirectUri = "com.example.app:/logout?state=$state&extra=1"
                val response = session.parseRedirect(redirectUri)
                assertEquals(state, response.state)
                // #164 expects exactly one additional parameter.
                assertEquals(1, response.additionalParameters.size)
                assertTrue(
                    response.additionalParameters.any {
                        it.name == "extra" && it.value == "1"
                    },
                )
            } finally {
                session.close()
            }
        } finally {
            config.close()
        }
    }

    @Test
    fun testE2() {
        val config =
            FfiServiceConfiguration(IDP_AUTHORIZE, IDP_TOKEN)
                .withEndSessionEndpoint(IDP_LOGOUT)
        try {
            val session =
                beginEndSession(
                    config,
                    FfiEndSessionOptions(
                        clientId = "c1",
                        idTokenHint = "id_token",
                        postLogoutRedirectUri = "com.example.app:/logout",
                    ),
                )
            try {
                // Keep the configured callback URI and vary only the state,
                // so the failure exercises the state comparison rather than
                // the URI match check that runs first.
                val error =
                    expectFfiException {
                        session.parseRedirect("com.example.app:/logout?state=wrong_state")
                    }
                assertTrue(
                    "E2: expected FfiException.InvalidResponse, got $error",
                    error is FfiException.InvalidResponse,
                )
            } finally {
                session.close()
            }
        } finally {
            config.close()
        }
    }

    @Test
    fun testE3() {
        val config =
            FfiServiceConfiguration(IDP_AUTHORIZE, IDP_TOKEN)
                .withEndSessionEndpoint(IDP_LOGOUT)
        try {
            val session =
                beginEndSession(
                    config,
                    FfiEndSessionOptions(
                        clientId = "c1",
                        idTokenHint = "id_token",
                        postLogoutRedirectUri = null,
                    ),
                )
            try {
                val error =
                    expectFfiException {
                        session.parseRedirect("https://idp.example/logout?state=s1")
                    }
                if (error is FfiException.InvalidResponse) {
                    // Assert the exact diagnostic so a state mismatch cannot
                    // stand in for the missing-redirect branch.
                    assertEquals(
                        "no post-logout redirect URI was requested",
                        error.v1,
                    )
                } else {
                    throw AssertionError(
                        "E3: expected FfiException.InvalidResponse, got $error"
                    )
                }
            } finally {
                session.close()
            }
        } finally {
            config.close()
        }
    }

    @Test
    fun testE4() {
        val config = FfiServiceConfiguration(IDP_AUTHORIZE, IDP_TOKEN)
        try {
            val error =
                expectFfiException {
                    beginEndSession(
                        config,
                        FfiEndSessionOptions(
                            clientId = "c1",
                            idTokenHint = "id_token",
                            postLogoutRedirectUri = "com.example.app:/logout",
                        ),
                    )
                }
            assertTrue(
                "E4: expected FfiException.InvalidRequest, got $error",
                error is FfiException.InvalidRequest,
            )
        } finally {
            config.close()
        }
    }

    @Test
    fun testE5() {
        val config =
            FfiServiceConfiguration(IDP_AUTHORIZE, IDP_TOKEN)
                .withEndSessionEndpoint(IDP_LOGOUT)
        try {
            val session =
                beginEndSession(
                    config,
                    FfiEndSessionOptions(
                        clientId = "c1",
                        idTokenHint = null,
                        postLogoutRedirectUri = null,
                    ),
                )
            try {
                val error =
                    expectFfiException { session.parseRedirect("not a url") }
                assertTrue(
                    "E5: expected FfiException.InvalidRequest, got $error",
                    error is FfiException.InvalidRequest,
                )
            } finally {
                session.close()
            }
        } finally {
            config.close()
        }
    }

    // MARK: - Authentication State JSON (S)

    @Test
    fun testS1() = runBlocking {
        val state = FfiAuthenticationState.fromJson(STATE_JSON)
        try {
            val serialized = state.toJson()
            val restored = FfiAuthenticationState.fromJson(serialized)
            try {
                assertEquals(serialized, restored.toJson())
                val response = restored.tokenResponse()
                assertEquals("old", response.accessToken)
                assertEquals("Bearer", response.tokenType)
                assertEquals("refresh", response.refreshToken)
            } finally {
                restored.close()
            }
        } finally {
            state.close()
        }
    }

    @Test
    fun testS2() {
        val error = expectFfiException { FfiAuthenticationState.fromJson("{") }
        assertTrue(
            "S2: expected FfiException.InvalidRequest, got $error",
            error is FfiException.InvalidRequest,
        )
    }

    // MARK: - Cancellation (C)
    //
    // The C tests must not order themselves against the operation with a
    // fixed delay: under CI load the child task may not have started, and the
    // test would pass on a pre-execution cancel without verifying in-flight
    // cancellation. Instead each test:
    //   1. waits, with a deadline, for the transport to report that it
    //      entered `execute`,
    //   2. cancels the shared handle, so the request is guaranteed in
    //      flight,
    //   3. waits, with a deadline, for the operation to complete,
    //   4. asserts the completion is `FfiException.Cancelled`.

    @Test
    fun testC1() = runBlocking {
        // discover must observe a cancellation issued while its request is
        // in flight.
        val transport = BlockingTransport()
        val cancellation = FfiCancellationHandle()
        try {
            val result =
                runCancellationProbe(transport.started, cancellation) {
                    FfiServiceConfiguration.discover(
                        "https://idp.example/",
                        transport,
                        it,
                    )
                }
            assertCancelled("C1", "discover", result)
        } finally {
            cancellation.close()
        }
    }

    @Test
    fun testC2() = runBlocking {
        // revoke must observe a cancellation issued while its request is in
        // flight.
        val transport = BlockingTransport()
        val cancellation = FfiCancellationHandle()
        val config =
            FfiServiceConfiguration(IDP_AUTHORIZE, IDP_TOKEN)
                .withRevocationEndpoint(IDP_REVOKE)
        try {
            val result =
                runCancellationProbe(transport.started, cancellation) {
                    revoke(config, "c1", "t1", null, transport, it)
                }
            assertCancelled("C2", "revoke", result)
        } finally {
            config.close()
            cancellation.close()
        }
    }

    @Test
    fun testC3() = runBlocking {
        // register_public_client must observe a cancellation issued while its
        // request is in flight.
        val transport = BlockingTransport()
        val cancellation = FfiCancellationHandle()
        val config =
            FfiServiceConfiguration(IDP_AUTHORIZE, IDP_TOKEN)
                .withRegistrationEndpoint(IDP_REGISTER)
        try {
            val result =
                runCancellationProbe(transport.started, cancellation) {
                    registerPublicClient(
                        config,
                        FfiRegistrationOptions(
                            redirectUris = listOf("https://app.example/callback"),
                            clientName = null,
                            initialAccessToken = null,
                        ),
                        transport,
                        it,
                    )
                }
            assertCancelled("C3", "register_public_client", result)
        } finally {
            config.close()
            cancellation.close()
        }
    }

    @Test
    fun testC4() = runBlocking {
        // refresh must observe a cancellation issued while its request is in
        // flight, and must leave the token state unchanged.
        val transport = BlockingTransport()
        val cancellation = FfiCancellationHandle()
        // Create a state using fromJson to avoid needing a real token
        // response.
        val state = FfiAuthenticationState.fromJson(STATE_JSON)
        val config = FfiServiceConfiguration(IDP_AUTHORIZE, IDP_TOKEN)
        try {
            val result =
                runCancellationProbe(transport.started, cancellation) {
                    state.refresh(config, "c1", emptyList(), transport, it)
                }
            assertCancelled("C4", "refresh", result)

            // A cancelled refresh must not update the token state.
            val response = state.tokenResponse()
            assertEquals("old", response.accessToken)
            assertEquals("Bearer", response.tokenType)
            assertEquals("refresh", response.refreshToken)
        } finally {
            config.close()
            state.close()
            cancellation.close()
        }
    }

    @Test
    fun testC5() = runBlocking {
        // The UnresponsiveTransport never answers after the handle fires, so
        // a Cancelled outcome can only be produced by the Rust core racing
        // the handle against the transport. Both revoke and refresh must
        // complete, within a deadline, with FfiException.Cancelled from the
        // core. discover and register_public_client lack this mechanism (it
        // is tracked in issue #183), so they are out of scope here.
        val baseConfig = FfiServiceConfiguration(IDP_AUTHORIZE, IDP_TOKEN)
        val revocationConfig = baseConfig.withRevocationEndpoint(IDP_REVOKE)
        try {
            val revokeTransport = UnresponsiveTransport()
            val revokeCancellation = FfiCancellationHandle()
            try {
                val result =
                    runCancellationProbe(revokeTransport.started, revokeCancellation) {
                        revoke(revocationConfig, "c1", "t1", null, revokeTransport, it)
                    }
                assertCancelled("C5", "revoke", result)
            } finally {
                revokeCancellation.close()
            }

            val state = FfiAuthenticationState.fromJson(STATE_JSON)
            val refreshTransport = UnresponsiveTransport()
            val refreshCancellation = FfiCancellationHandle()
            try {
                val result =
                    runCancellationProbe(refreshTransport.started, refreshCancellation) {
                        state.refresh(baseConfig, "c1", emptyList(), refreshTransport, it)
                    }
                assertCancelled("C5", "refresh", result)
            } finally {
                state.close()
                refreshCancellation.close()
            }
        } finally {
            revocationConfig.close()
            baseConfig.close()
        }
    }

    private fun assertCancelled(
        id: String,
        operation: String,
        result: CancellationResult,
    ) {
        assertTrue(
            "$id: transport.execute was not entered within 10 seconds",
            result.entered,
        )
        val outcome = result.outcome
        assertNotNull(
            "$id: $operation did not complete within 10 seconds after cancellation",
            outcome,
        )
        val error = outcome!!.error
        assertTrue(
            "$id: expected FfiException.Cancelled, got $error",
            error is FfiException.Cancelled,
        )
    }
}

/**
 * Token state JSON in the shape produced by `FfiAuthenticationState.toJson()`.
 */
private const val STATE_JSON =
    """{"token_response":{"access_token":"old","token_type":"Bearer","refresh_token":"refresh"}}"""

/**
 * Discovery document for `https://idp.example/` with every required and
 * optional endpoint present.
 */
private const val DISCOVERY_DOCUMENT =
    """{"issuer":"https://idp.example/","authorization_endpoint":"https://idp.example/authorize","token_endpoint":"https://idp.example/token","revocation_endpoint":"https://idp.example/revoke","registration_endpoint":"https://idp.example/register","end_session_endpoint":"https://idp.example/logout","jwks_uri":"https://idp.example/.well-known/jwks.json"}"""

/**
 * A discovery document whose issuer does not match the requested one.
 */
private const val DISCOVERY_ISSUER_MISMATCH =
    """{"issuer":"https://other.example/","authorization_endpoint":"https://idp.example/authorize","token_endpoint":"https://idp.example/token"}"""

private const val PUBLIC_CLIENT_RESPONSE =
    """{"client_id":"c1","application_type":"native","token_endpoint_auth_method":"none"}"""

private const val IDP_AUTHORIZE = "https://idp.example/authorize"
private const val IDP_TOKEN = "https://idp.example/token"
private const val IDP_REVOKE = "https://idp.example/revoke"
private const val IDP_REGISTER = "https://idp.example/register"
private const val IDP_LOGOUT = "https://idp.example/logout"

/**
 * A fake transport that records requests and returns a scripted result. The
 * result is either a predefined [FfiHttpResponse] or an error to throw, so
 * the tests can exercise both response parsing and error conversion through
 * the generated bindings.
 */
private class ScriptedTransport : NativeHttpTransport {
    private val lock = Any()
    private val requests = mutableListOf<FfiHttpRequest>()
    var response: Result<FfiHttpResponse>? = null

    val recordedRequests: List<FfiHttpRequest>
        get() {
            synchronized(lock) {
                return requests.toList()
            }
        }

    override suspend fun execute(
        request: FfiHttpRequest,
        cancellation: FfiCancellationHandle,
    ): FfiHttpResponse {
        synchronized(lock) {
            requests.add(request)
        }
        val scripted =
            response ?: error("No response configured for ScriptedTransport")
        return scripted.getOrThrow()
    }
}

/**
 * A transport that simulates a long-running request. It signals the test
 * when it enters `execute`, then waits for the cancellation handle to fire
 * before throwing `FfiException.Cancelled`.
 */
private class BlockingTransport : NativeHttpTransport {
    val started = AtomicBoolean(false)

    override suspend fun execute(
        request: FfiHttpRequest,
        cancellation: FfiCancellationHandle,
    ): FfiHttpResponse {
        started.set(true)
        cancellation.cancelled()
        throw FfiException.Cancelled()
    }
}

/**
 * A transport that never answers its request. It signals the test when it
 * enters `execute`, waits for the cancellation handle to fire, and then
 * suspends without ever returning a response or an error. Used by C5:
 * because the transport cannot produce the result, a `FfiException.Cancelled`
 * outcome can only come from the Rust core racing the handle against the
 * transport. When Rust wins the race it drops the foreign future and the
 * UniFFI drop callback cancels this coroutine, so the delay must throw to
 * exit the loop (a swallowed exception would spin at full CPU on every
 * iteration).
 */
private class UnresponsiveTransport : NativeHttpTransport {
    val started = AtomicBoolean(false)

    override suspend fun execute(
        request: FfiHttpRequest,
        cancellation: FfiCancellationHandle,
    ): FfiHttpResponse {
        started.set(true)
        cancellation.cancelled()
        while (true) {
            delay(1_000)
        }
    }
}

/**
 * The recorded completion of an operation run in a background coroutine:
 * null on success, otherwise the thrown error.
 */
private class OperationOutcome(val error: Throwable?)

private class CancellationResult(
    val entered: Boolean,
    val outcome: OperationOutcome?,
)

/**
 * Runs [operation] in a background coroutine of the receiver scope, then
 * performs the bounded in-flight cancellation sequence:
 *
 * 1. waits, with a deadline, for [started] to be set by the transport;
 * 2. cancels the shared [cancellation] handle;
 * 3. waits, with a deadline, for the operation to complete.
 *
 * Kotlin coroutines make the completion awaitable and cancellable, so no
 * extra polling box is needed the way the Swift tests require. The pending
 * operation is always cancelled on exit so a test failure cannot leak a
 * running operation.
 */
private suspend fun CoroutineScope.runCancellationProbe(
    started: AtomicBoolean,
    cancellation: FfiCancellationHandle,
    deadlineMillis: Long = 10_000,
    operation: suspend (FfiCancellationHandle) -> Unit,
): CancellationResult {
    val pending =
        async {
            try {
                operation(cancellation)
                OperationOutcome(null)
            } catch (error: Throwable) {
                OperationOutcome(error)
            }
        }
    return try {
        val entered =
            withTimeoutOrNull(deadlineMillis) {
                while (!started.get()) {
                    delay(5)
                }
                true
            } == true
        val outcome =
            if (entered) {
                cancellation.cancel()
                withTimeoutOrNull(deadlineMillis) { pending.await() }
            } else {
                null
            }
        CancellationResult(entered, outcome)
    } finally {
        pending.cancel()
    }
}

/**
 * Runs [block] and returns the thrown `FfiException`; fails the test if the
 * block completes without throwing one.
 */
private fun <T> expectFfiException(block: () -> T): FfiException {
    try {
        block()
    } catch (error: FfiException) {
        return error
    }
    throw AssertionError("Expected FfiException")
}

/**
 * Suspended variant of [expectFfiException] for async operations.
 */
private suspend fun <T> expectFfiExceptionAsync(block: suspend () -> T): FfiException {
    try {
        block()
    } catch (error: FfiException) {
        return error
    }
    throw AssertionError("Expected FfiException")
}

/**
 * Decodes a form-urlencoded request body into all fields as [name, value]
 * pairs, preserving duplicates and empty values. Pairs are sorted by name,
 * then value, so the comparison is independent of the serializer's field
 * order while still rejecting a renamed, duplicated, or emptied field.
 */
private fun formFields(body: ByteArray): List<List<String>> {
    val text = String(body, StandardCharsets.UTF_8)
    return text
        .split("&")
        .map { pair ->
            val parts = pair.split("=", limit = 2)
            val name = parts[0]
            val rawValue = if (parts.size > 1) parts[1] else ""
            // URLDecoder also maps '+' to a space; percent-decode only, to
            // match the Swift test's removingPercentEncoding.
            val value = URLDecoder.decode(rawValue.replace("+", "%2B"), StandardCharsets.UTF_8)
            listOf(name, value)
        }
        .sortedWith(compareBy({ it[0] }, { it[1] }))
}
