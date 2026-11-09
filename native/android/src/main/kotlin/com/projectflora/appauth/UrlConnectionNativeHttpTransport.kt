package com.projectflora.appauth

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import uniffi.appauth_rust.FfiCancellationHandle
import uniffi.appauth_rust.FfiException
import uniffi.appauth_rust.FfiHttpHeader
import uniffi.appauth_rust.FfiHttpRequest
import uniffi.appauth_rust.FfiHttpResponse
import uniffi.appauth_rust.NativeHttpTransport
import java.io.IOException
import java.net.HttpURLConnection
import java.net.MalformedURLException
import java.net.URL
import java.nio.charset.StandardCharsets
import kotlin.coroutines.resumeWithException

/**
 * `HttpURLConnection`-based UniFFI transport that does not follow redirects.
 *
 * The implementation disconnects active connections when the coroutine or
 * shared cancellation handle is cancelled.
 */
class UrlConnectionNativeHttpTransport : NativeHttpTransport {
    override suspend fun execute(
        request: FfiHttpRequest,
        cancellation: FfiCancellationHandle,
    ): FfiHttpResponse {
        val connection = openConnection(request.url)
        connection.instanceFollowRedirects = false
        val cancellationScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val cancellationWatcher =
            cancellationScope.launch {
                cancellation.cancelled()
                connection.disconnect()
            }

        return suspendCancellableCoroutine { continuation ->
            continuation.invokeOnCancellation {
                cancellation.cancel()
                connection.disconnect()
                cancellationScope.cancel()
            }
            Dispatchers.IO.dispatch(continuation.context) {
                try {
                    if (!continuation.isActive) return@dispatch
                    if (cancellation.isCancelled()) throw FfiException.Cancelled()
                    continuation.resumeWith(Result.success(executeRequest(connection, request, cancellation)))
                } catch (error: FfiException) {
                    continuation.resumeWithException(error)
                } catch (error: IOException) {
                    val failure =
                        if (cancellation.isCancelled()) {
                            FfiException.Cancelled()
                        } else {
                            FfiException.TransportFailure(error.message ?: "HTTP request failed")
                        }
                    continuation.resumeWithException(failure)
                } catch (error: IllegalArgumentException) {
                    continuation.resumeWithException(
                        FfiException.InvalidRequest(error.message ?: "HTTP request is invalid"),
                    )
                } catch (error: SecurityException) {
                    continuation.resumeWithException(
                        FfiException.TransportFailure(error.message ?: "HTTP request was denied"),
                    )
                } finally {
                    cancellationWatcher.cancel()
                    cancellationScope.cancel()
                    connection.disconnect()
                }
            }
        }
    }

    private fun openConnection(requestUrl: String): HttpURLConnection {
        val url =
            try {
                URL(requestUrl)
            } catch (_: MalformedURLException) {
                throw FfiException.InvalidRequest("HTTP request URL is invalid")
            }
        return try {
            url.openConnection() as HttpURLConnection
        } catch (_: ClassCastException) {
            throw FfiException.InvalidRequest("HTTP request URL must use HTTP or HTTPS")
        } catch (error: SecurityException) {
            throw FfiException.TransportFailure(error.message ?: "HTTP request was denied")
        }
    }

    private fun executeRequest(
        connection: HttpURLConnection,
        request: FfiHttpRequest,
        cancellation: FfiCancellationHandle,
    ): FfiHttpResponse {
        connection.requestMethod = request.method
        request.headers.forEach { header ->
            val value = String(header.value, StandardCharsets.ISO_8859_1)
            connection.addRequestProperty(header.name, value)
        }
        if (request.body.isNotEmpty()) {
            connection.doOutput = true
            connection.outputStream.use { it.write(request.body) }
        }

        val status = connection.responseCode
        if (cancellation.isCancelled()) throw FfiException.Cancelled()
        val body = readResponseBody(connection, request.method, status)
        val headers =
            connection.headerFields.flatMap { (name, values) ->
                if (name == null) {
                    emptyList()
                } else {
                    values.orEmpty().map { value ->
                        FfiHttpHeader(
                            name = name,
                            value = value.toByteArray(StandardCharsets.ISO_8859_1),
                        )
                    }
                }
            }
        if (cancellation.isCancelled()) throw FfiException.Cancelled()
        return FfiHttpResponse(status.toUShort(), headers, body)
    }

    private fun readResponseBody(
        connection: HttpURLConnection,
        method: String,
        status: Int,
    ): ByteArray {
        if (method.equals("HEAD", ignoreCase = true) || status == 204 || status == 304) {
            return byteArrayOf()
        }
        val stream =
            connection.errorStream ?: try {
                connection.inputStream
            } catch (_: IOException) {
                null
            }
        return stream?.use { it.readBytes() } ?: byteArrayOf()
    }
}
