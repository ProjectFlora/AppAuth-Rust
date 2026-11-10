package com.projectflora.appauth

import android.net.Uri
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.appauth_rust.FfiAuthorizationOptions
import uniffi.appauth_rust.FfiServiceConfiguration
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.ServerSocket
import java.net.SocketTimeoutException
import java.net.URL
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

@RunWith(AndroidJUnit4::class)
class AndroidExternalBrowserAuthorizationTest {
    @Test
    fun customTabAuthorizationReturnsThroughCallbackAndExchangesCode() = runBlocking {
        MockAuthorizationServer().use { server ->
            val device = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation())
            prepareChrome(device)

            val healthConnection =
                URL("${server.baseUrl}/health").openConnection() as HttpURLConnection
            try {
                assertEquals(200, healthConnection.responseCode)
            } finally {
                healthConnection.disconnect()
            }

            val scenario = ActivityScenario.launch(AndroidAuthorizationFlowTestActivity::class.java)
            try {
                val result = CompletableDeferred<Result<uniffi.appauth_rust.FfiAuthenticationState>>()
                val redirectUri = "com.example.app:/oauth/callback"
                scenario.onActivity { activity ->
                    activity.authorize(
                        configuration =
                            FfiServiceConfiguration(
                                "${server.baseUrl}/authorize",
                                "${server.baseUrl}/token",
                            ),
                        options =
                            FfiAuthorizationOptions(
                                "mock-client",
                                redirectUri,
                                listOf("profile"),
                                emptyList(),
                                emptyList(),
                            ),
                        redirects = AndroidRedirectConfiguration(null, redirectUri),
                        transport = UrlConnectionNativeHttpTransport(),
                    ) { result.complete(it) }
                }

                val authorizationParameters =
                    withTimeoutOrNull(30_000) {
                        select<Map<String, String>> {
                            server.authorizationRequest.onAwait { it }
                            result.onAwait {
                                it.getOrThrow()
                                throw AssertionError("Authorization completed without opening the mock provider")
                            }
                        }
                    } ?: throw AssertionError("External browser did not open the mock provider")
                assertEquals("code", authorizationParameters["response_type"])
                assertEquals("mock-client", authorizationParameters["client_id"])
                assertEquals(redirectUri, authorizationParameters["redirect_uri"])
                assertEquals("S256", authorizationParameters["code_challenge_method"])

                assertTrue(
                    "Mock provider page did not load in the external browser",
                    device.wait(Until.hasObject(By.text("Authorize")), 20_000),
                )
                checkNotNull(device.findObject(By.text("Authorize"))).click()
                confirmExternalAppLaunch(device)

                val tokenParameters =
                    withTimeoutOrNull(30_000) {
                        select<Map<String, String>> {
                            server.tokenRequest.onAwait { it }
                            result.onAwait {
                                it.getOrThrow()
                                throw AssertionError("Authorization completed before token exchange")
                            }
                        }
                    } ?: throw AssertionError("Browser callback did not reach the token endpoint")
                assertEquals("authorization_code", tokenParameters["grant_type"])
                assertEquals("mock-code", tokenParameters["code"])
                assertEquals(redirectUri, tokenParameters["redirect_uri"])
                val codeVerifier = tokenParameters["code_verifier"].orEmpty()
                assertTrue(codeVerifier.length in 43..128)
                val expectedChallenge =
                    Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(
                            MessageDigest.getInstance("SHA-256")
                                .digest(codeVerifier.toByteArray(StandardCharsets.UTF_8)),
                        )
                assertEquals(authorizationParameters["code_challenge"], expectedChallenge)

                val authenticationState =
                    withTimeoutOrNull(30_000) { result.await().getOrThrow() }
                        ?: throw AssertionError("Token exchange did not complete")
                assertEquals("mock-access-token", authenticationState.tokenResponse().accessToken)
                server.throwIfFailed()
            } finally {
                scenario.close()
            }
        }
    }

    private fun prepareChrome(device: UiDevice) {
        device.executeShellCommand("am start -a android.intent.action.VIEW -d about:blank -p com.android.chrome")
        assertTrue(
            "Chrome did not open before the authorization flow",
            device.wait(Until.hasObject(By.pkg("com.android.chrome")), 20_000),
        )

        val setupDeadline = System.currentTimeMillis() + 15_000
        val setupLabels = listOf("Accept & continue", "No thanks", "Use without an account")
        while (System.currentTimeMillis() < setupDeadline) {
            val setupButton = setupLabels.firstNotNullOfOrNull { label ->
                device.findObject(By.text(label))
            }
            if (setupButton == null) {
                Thread.sleep(500)
            } else {
                setupButton.click()
            }
        }
        device.pressBack()
    }

    private fun confirmExternalAppLaunch(device: UiDevice) {
        val labels = listOf("Just once", "Open", "Continue")
        for (label in labels) {
            if (device.wait(Until.hasObject(By.text(label)), 2_000)) {
                device.findObject(By.text(label))?.click()
                return
            }
        }
    }
}

private class MockAuthorizationServer : Closeable {
    private val serverSocket =
        ServerSocket(0, 8, InetAddress.getByName("127.0.0.1"))
    private val stopped = AtomicBoolean(false)
    private val failure = AtomicReference<Throwable?>()
    private val connectionExecutor = Executors.newCachedThreadPool()
    private val serverThread =
        Thread({ serve() }, "mock-oauth-provider").apply {
            isDaemon = true
            start()
        }

    val baseUrl = "http://127.0.0.1:${serverSocket.localPort}"
    val authorizationRequest = CompletableDeferred<Map<String, String>>()
    val tokenRequest = CompletableDeferred<Map<String, String>>()

    override fun close() {
        stopped.set(true)
        serverSocket.close()
        connectionExecutor.shutdownNow()
        serverThread.join(1_000)
    }

    fun throwIfFailed() {
        failure.get()?.let { throw AssertionError("Mock OAuth server failed", it) }
    }

    private fun serve() {
        while (!stopped.get()) {
            try {
                val socket = serverSocket.accept()
                connectionExecutor.execute {
                    try {
                        socket.use { handle(it) }
                    } catch (_: SocketTimeoutException) {
                        // Browsers can open speculative connections before sending a request.
                    } catch (error: Exception) {
                        recordFailure(error)
                    }
                }
            } catch (error: Exception) {
                if (!stopped.get()) {
                    recordFailure(error)
                }
            }
        }
    }

    private fun recordFailure(error: Exception) {
        if (failure.compareAndSet(null, error)) {
            authorizationRequest.completeExceptionally(error)
            tokenRequest.completeExceptionally(error)
        }
    }

    private fun handle(socket: java.net.Socket) {
        socket.soTimeout = 10_000
        val input = BufferedInputStream(socket.getInputStream())
        val output = BufferedOutputStream(socket.getOutputStream())
        val requestLine = readLine(input) ?: return
        val headers = mutableMapOf<String, String>()
        while (true) {
            val line = readLine(input) ?: return
            if (line.isEmpty()) break
            val separator = line.indexOf(':')
            if (separator > 0) {
                headers[line.substring(0, separator).trim().lowercase()] =
                    line.substring(separator + 1).trim()
            }
        }

        val bodyLength = headers["content-length"]?.toIntOrNull() ?: 0
        val body = ByteArray(bodyLength)
        input.readFully(body)
        val requestTarget = requestLine.split(' ').getOrNull(1) ?: "/"
        val uri = Uri.parse("$baseUrl$requestTarget")

        when (uri.path) {
            "/health" -> respond(output, 200, "text/plain", "ok".toByteArray())
            "/authorize" -> {
                val parameters = parseForm(uri.encodedQuery.orEmpty())
                authorizationRequest.complete(parameters)
                val redirect = Uri.parse(parameters.getValue("redirect_uri"))
                    .buildUpon()
                    .appendQueryParameter("code", "mock-code")
                    .appendQueryParameter("state", parameters.getValue("state"))
                    .build()
                val html =
                    """<!doctype html><meta charset="utf-8"><button onclick="location.href='$redirect'">Authorize</button>"""
                respond(output, 200, "text/html; charset=utf-8", html.toByteArray())
            }
            "/token" -> {
                val parameters =
                    parseForm(String(body, StandardCharsets.UTF_8))
                tokenRequest.complete(parameters)
                val response =
                    """{"access_token":"mock-access-token","token_type":"Bearer","expires_in":3600,"refresh_token":"mock-refresh-token","scope":"profile"}"""
                respond(output, 200, "application/json", response.toByteArray())
            }
            else -> respond(output, 404, "text/plain", byteArrayOf())
        }
    }

    private fun respond(
        output: BufferedOutputStream,
        status: Int,
        contentType: String,
        body: ByteArray,
    ) {
        val reason = if (status == 200) "OK" else "Not Found"
        val headers =
            "HTTP/1.1 $status $reason\r\n" +
                "Content-Type: $contentType\r\n" +
                "Content-Length: ${body.size}\r\n" +
                "Cache-Control: no-store\r\n" +
                "Connection: close\r\n\r\n"
        output.write(headers.toByteArray(StandardCharsets.US_ASCII))
        output.write(body)
        output.flush()
    }

    private fun parseForm(value: String): Map<String, String> =
        value
            .split('&')
            .filter(String::isNotEmpty)
            .associate { field ->
                val separator = field.indexOf('=')
                val name = if (separator < 0) field else field.substring(0, separator)
                val content = if (separator < 0) "" else field.substring(separator + 1)
                URLDecoder.decode(name, StandardCharsets.UTF_8.name()) to
                    URLDecoder.decode(content, StandardCharsets.UTF_8.name())
            }

    private fun readLine(input: BufferedInputStream): String? {
        val bytes = ByteArrayOutputStream()
        while (true) {
            val value = input.read()
            if (value < 0) return if (bytes.size() == 0) null else bytes.toString("US-ASCII")
            if (value == '\n'.code) break
            if (value != '\r'.code) bytes.write(value)
        }
        return bytes.toString("US-ASCII")
    }
}

private fun BufferedInputStream.readFully(target: ByteArray) {
    var offset = 0
    while (offset < target.size) {
        val count = read(target, offset, target.size - offset)
        if (count < 0) throw IllegalStateException("Request body ended early")
        offset += count
    }
}
