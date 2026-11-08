package com.projectflora.appauth

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.appauth_rust.FfiCancellationHandle
import uniffi.appauth_rust.FfiException
import uniffi.appauth_rust.FfiHttpRequest
import uniffi.appauth_rust.NoHandle
import java.io.BufferedReader
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.nio.charset.StandardCharsets
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class UrlConnectionNativeHttpTransportTest {
    @Test
    fun doesNotFollowHttpRedirects() =
        runBlocking {
            val server =
                LocalHttpServer(
                    responses =
                        listOf(
                            "HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        ),
                )
            try {
                val response =
                    UrlConnectionNativeHttpTransport().execute(
                        request(server.url),
                        TestCancellationHandle(),
                    )

                assertEquals(302.toUShort(), response.status)
            } finally {
                server.close()
            }
        }

    @Test
    fun cancellationDisconnectsAnActiveRequest() =
        runBlocking {
            val server = LocalHttpServer(responses = listOf(null))
            val cancellation = TestCancellationHandle()
            try {
                val pendingRequest =
                    async {
                        try {
                            UrlConnectionNativeHttpTransport().execute(request(server.url), cancellation)
                        } catch (error: FfiException.Cancelled) {
                            error
                        }
                    }
                assertTrue(
                    withContext(Dispatchers.IO) {
                        server.received.await(5, TimeUnit.SECONDS)
                    },
                )
                cancellation.cancel()

                val result = withTimeout(5_000) { pendingRequest.await() }
                assertTrue(result is FfiException.Cancelled)
            } finally {
                server.close()
            }
        }

    @Test
    fun coroutineCancellationDisconnectsAnActiveRequest() =
        runBlocking {
            val server = LocalHttpServer(responses = listOf(null))
            val cancellation = TestCancellationHandle()
            try {
                val pendingRequest =
                    async {
                        UrlConnectionNativeHttpTransport().execute(request(server.url), cancellation)
                    }
                assertTrue(
                    withContext(Dispatchers.IO) {
                        server.received.await(5, TimeUnit.SECONDS)
                    },
                )

                withTimeout(5_000) {
                    pendingRequest.cancelAndJoin()
                }

                assertTrue(cancellation.isCancelled())
            } finally {
                server.close()
            }
        }

    private fun request(url: String) =
        FfiHttpRequest(
            method = "GET",
            url = url,
            headers = emptyList(),
            body = byteArrayOf(),
        )
}

private class TestCancellationHandle : FfiCancellationHandle(NoHandle) {
    private val signal = CompletableDeferred<Unit>()

    override fun cancel() {
        signal.complete(Unit)
    }

    override fun isCancelled(): Boolean = signal.isCompleted

    override suspend fun cancelled() {
        signal.await()
    }
}

private class LocalHttpServer(
    responses: List<String?>,
) : AutoCloseable {
    private val server = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
    val url: String = "http://127.0.0.1:${server.localPort}/start"
    val received = CountDownLatch(1)
    private val worker =
        Thread {
            try {
                for (response in responses) {
                    server.accept().use { socket ->
                        val reader =
                            BufferedReader(
                                socket.getInputStream().reader(StandardCharsets.ISO_8859_1),
                            )
                        while (reader.readLine()?.isNotEmpty() == true) {
                        }
                        received.countDown()
                        if (response == null) {
                            while (socket.getInputStream().read() != -1) {
                            }
                        } else {
                            socket.getOutputStream().use { output ->
                                output.write(response.toByteArray(StandardCharsets.ISO_8859_1))
                                output.flush()
                            }
                        }
                    }
                }
            } catch (_: IOException) {
            }
        }.apply {
            isDaemon = true
            start()
        }

    override fun close() {
        server.close()
        worker.join(1_000)
    }
}
