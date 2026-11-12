package com.projectflora.appauth

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.verify.domain.DomainVerificationManager
import android.content.pm.verify.domain.DomainVerificationUserState
import android.net.Uri
import android.os.Bundle
import androidx.browser.customtabs.CustomTabsIntent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import uniffi.appauth_rust.FfiAuthenticationState
import uniffi.appauth_rust.FfiAuthorizationOptions
import uniffi.appauth_rust.FfiCancellationHandle
import uniffi.appauth_rust.FfiException
import uniffi.appauth_rust.FfiServiceConfiguration
import uniffi.appauth_rust.NativeHttpTransport
import uniffi.appauth_rust.beginAuthorization
import java.net.URI
import java.net.URISyntaxException
import java.util.concurrent.atomic.AtomicReference

/**
 * Configures redirect URIs used by [AndroidAuthorizationAdapter].
 *
 * When both URIs are supplied, a verified App Link is preferred and the
 * custom-scheme URI is the fallback.
 *
 * @property appLinkUri HTTPS App Link callback URI, or `null` when unavailable.
 * @property customSchemeUri Registered custom-scheme callback URI, or `null` when unavailable.
 */
data class AndroidRedirectConfiguration(
    val appLinkUri: String?,
    val customSchemeUri: String?,
)

/** Errors raised while preparing or running Android browser authorization. */
sealed class AndroidAuthorizationAdapterException(
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause) {
    /** An authorization operation is already active on this adapter. */
    class AuthorizationAlreadyRunning : AndroidAuthorizationAdapterException("An authorization is already running")

    /** A configured callback URI is invalid or cannot be routed to the callback activity. */
    class InvalidRedirectConfiguration(
        message: String,
    ) : AndroidAuthorizationAdapterException(message)

    /** No external browser could be opened for authorization. */
    class BrowserUnavailable(
        cause: Throwable,
    ) : AndroidAuthorizationAdapterException("No browser is available for authorization", cause)

    /** The host application has not registered the callback activity for the selected URI. */
    class CallbackActivityNotRegistered :
        AndroidAuthorizationAdapterException(
            "Register AndroidAuthorizationCallbackActivity for the configured redirect URI",
        )
}

/**
 * Runs OAuth authorization in an external browser Custom Tab.
 *
 * The host application must register [AndroidAuthorizationCallbackActivity]
 * and its configured redirect URI intent filters in the manifest.
 */
class AndroidAuthorizationAdapter(
    private val activity: Activity,
) {
    private val activeOperation = AtomicReference<AuthorizationOperation?>()

    /**
     * Selects a verified App Link or registered custom-scheme redirect, opens
     * the browser, validates the callback, and exchanges its authorization code.
     *
     * Only one operation may run on an adapter at a time. Coroutine
     * cancellation and [cancel] stop the callback wait and in-flight request.
     */
    suspend fun authorize(
        configuration: FfiServiceConfiguration,
        options: FfiAuthorizationOptions,
        redirectConfiguration: AndroidRedirectConfiguration,
        transport: NativeHttpTransport,
    ): FfiAuthenticationState {
        val cancellation = FfiCancellationHandle()
        val operation = AuthorizationOperation(cancellation)
        if (!activeOperation.compareAndSet(null, operation)) {
            cancellation.close()
            throw AndroidAuthorizationAdapterException.AuthorizationAlreadyRunning()
        }

        return try {
            val redirectUri = selectRedirectUri(redirectConfiguration)
            val authorization =
                beginAuthorization(
                    configuration = configuration,
                    options = options.copy(redirectUri = redirectUri),
                    transport = transport,
                )
            try {
                val redirect = AndroidAuthorizationCallbackRegistry.register(redirectUri)
                operation.attach(redirect)
                withContext(Dispatchers.Main.immediate) {
                    if (!operation.launchIfActive {
                            if (activity.isFinishing || activity.isDestroyed) {
                                throw AndroidAuthorizationAdapterException.BrowserUnavailable(
                                    IllegalStateException("The host activity is not available"),
                                )
                            }
                            try {
                                CustomTabsIntent
                                    .Builder()
                                    .setShowTitle(true)
                                    .build()
                                    .launchUrl(activity, Uri.parse(authorization.authorizationUrl()))
                            } catch (error: ActivityNotFoundException) {
                                throw AndroidAuthorizationAdapterException.BrowserUnavailable(error)
                            }
                        }
                    ) {
                        throw FfiException.Cancelled()
                    }
                }

                currentCoroutineContext().ensureActive()
                val callbackUri = redirect.await()
                currentCoroutineContext().ensureActive()
                val response = authorization.parseRedirect(callbackUri)
                try {
                    authorization.exchangeCode(response, cancellation)
                } finally {
                    response.close()
                }
            } finally {
                authorization.close()
            }
        } catch (error: CancellationException) {
            operation.cancel()
            throw error
        } finally {
            operation.close()
            activeOperation.compareAndSet(operation, null)
            cancellation.close()
        }
    }

    /** Cancels the active browser callback wait and in-flight core request. */
    fun cancel() {
        activeOperation.get()?.cancel()
    }

    private fun selectRedirectUri(redirects: AndroidRedirectConfiguration): String =
        AndroidRedirectSelector.select(
            redirects = redirects,
            isVerifiedAppLink = { uri -> isVerifiedAppLink(Uri.parse(uri.toString())) },
            resolvesToCallbackActivity = { uri ->
                resolvesToCallbackActivity(Uri.parse(uri.toString()))
            },
        )

    private fun isVerifiedAppLink(uri: Uri): Boolean {
        val manager =
            activity.getSystemService(DomainVerificationManager::class.java)
                ?: return false
        val state = manager.getDomainVerificationUserState(activity.packageName) ?: return false
        if (!state.isLinkHandlingAllowed) return false
        val hostState =
            uri.host
                ?.let(AndroidRedirectSelector::normalizedHost)
                ?.let(state.hostToStateMap::get)
        return hostState == DomainVerificationUserState.DOMAIN_STATE_VERIFIED
    }

    private fun resolvesToCallbackActivity(uri: Uri): Boolean {
        val intent =
            Intent(Intent.ACTION_VIEW, uri)
                .addCategory(Intent.CATEGORY_DEFAULT)
                .addCategory(Intent.CATEGORY_BROWSABLE)
                .setPackage(activity.packageName)
        val resolved =
            activity.packageManager.resolveActivity(
                intent,
                PackageManager.MATCH_DEFAULT_ONLY,
            )
        return resolved?.activityInfo?.name == AndroidAuthorizationCallbackActivity::class.java.name
    }
}

/**
 * Receives OAuth callbacks and delivers them to the active authorization.
 *
 * Declare this activity as exported with browsable intent filters for each
 * configured redirect URI in the host application's manifest.
 */
class AndroidAuthorizationCallbackActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        AndroidAuthorizationCallbackRegistry.deliver(intent?.dataString)
        finish()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        AndroidAuthorizationCallbackRegistry.deliver(intent.dataString)
        finish()
    }
}

private class AuthorizationOperation(
    private val cancellation: FfiCancellationHandle,
) {
    private var redirect: PendingRedirect? = null
    private var isCancelled = false
    private var isClosed = false

    @Synchronized
    fun attach(redirect: PendingRedirect) {
        if (isClosed) {
            redirect.close()
            return
        }
        this.redirect = redirect
        if (isCancelled) {
            redirect.cancel()
        }
    }

    @Synchronized
    fun launchIfActive(launch: () -> Unit): Boolean {
        if (isCancelled || isClosed) return false
        launch()
        return true
    }

    @Synchronized
    fun cancel() {
        if (isClosed) return
        isCancelled = true
        cancellation.cancel()
        redirect?.cancel()
    }

    @Synchronized
    fun close() {
        if (isClosed) return
        isClosed = true
        val pending = redirect
        redirect = null
        AndroidAuthorizationCallbackRegistry.unregister(pending)
    }
}

internal class PendingRedirect(
    val expected: RedirectTarget,
) : AutoCloseable {
    private val result = CompletableDeferred<String>()

    val isCompleted: Boolean
        get() = result.isCompleted

    suspend fun await(): String = result.await()

    fun matches(uri: String): Boolean {
        // Route by target components only. A malformed query or fragment on
        // the matching route must reach core validation and terminate, rather
        // than being ignored and leaving the authorization pending forever.
        val actual = RedirectTarget.parse(uri.substringBefore('?').substringBefore('#')) ?: return false
        return expected.matches(actual)
    }

    fun cancel() {
        result.completeExceptionally(FfiException.Cancelled())
    }

    fun deliver(uri: String): Boolean = result.complete(uri)

    override fun close() {
        result.cancel()
    }
}

internal data class RedirectTarget(
    val scheme: String,
    val host: String?,
    val port: Int,
    val path: String,
) {
    fun matches(other: RedirectTarget): Boolean =
        scheme.equals(other.scheme, ignoreCase = true) &&
            (host?.equals(other.host, ignoreCase = true) ?: (other.host == null)) &&
            port == other.port &&
            normalizedPath(path) == normalizedPath(other.path)

    companion object {
        fun parse(value: String): RedirectTarget? {
            val uri =
                try {
                    URI(value)
                } catch (_: URISyntaxException) {
                    return null
                }
            if (!uri.isAbsolute || uri.rawFragment != null || uri.rawUserInfo != null) return null
            val host =
                try {
                    uri.host?.let(AndroidRedirectSelector::normalizedHost)
                } catch (_: IllegalArgumentException) {
                    return null
                }
            return RedirectTarget(
                scheme = uri.scheme,
                host = host,
                port =
                    when {
                        uri.port != -1 -> uri.port
                        uri.scheme.equals("https", ignoreCase = true) -> 443
                        uri.scheme.equals("http", ignoreCase = true) -> 80
                        else -> -1
                    },
                path = uri.rawPath.orEmpty(),
            )
        }

        private fun normalizedPath(path: String): String = if (path.isEmpty()) "/" else path
    }
}

internal object AndroidAuthorizationCallbackRegistry {
    private val lock = Any()
    private var pending: PendingRedirect? = null

    fun register(uri: String): PendingRedirect =
        synchronized(lock) {
            if (pending != null) {
                throw AndroidAuthorizationAdapterException.AuthorizationAlreadyRunning()
            }
            val redirect =
                PendingRedirect(
                    expected =
                        RedirectTarget.parse(uri)
                            ?: throw AndroidAuthorizationAdapterException.InvalidRedirectConfiguration(
                                "The redirect URI is invalid",
                            ),
                )
            pending = redirect
            redirect
        }

    fun deliver(uri: String?) {
        if (uri == null) return
        synchronized(lock) {
            val current = pending ?: return
            if (current.matches(uri)) {
                pending = null
                current.deliver(uri)
            }
        }
    }

    fun unregister(redirect: PendingRedirect?) {
        if (redirect == null) return
        synchronized(lock) {
            if (pending === redirect) pending = null
        }
        redirect.close()
    }
}
