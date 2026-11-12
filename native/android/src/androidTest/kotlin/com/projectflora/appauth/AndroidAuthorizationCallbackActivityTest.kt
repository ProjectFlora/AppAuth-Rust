package com.projectflora.appauth

import android.content.Intent
import android.net.Uri
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AndroidAuthorizationCallbackActivityTest {
    @Test
    fun customSchemeIntentReachesRegisteredCallback() =
        assertCallbackDelivered(
            redirectUri = "com.example.app:/oauth/callback",
            callbackUri = "com.example.app:/oauth/callback?code=auth-code&state=state",
        )

    @Test
    fun appLinkIntentReachesRegisteredCallback() =
        assertCallbackDelivered(
            redirectUri = "https://login.example.test/oauth/callback",
            callbackUri = "https://login.example.test/oauth/callback?code=auth-code&state=state",
        )

    @Test
    fun duplicateActivityCallbacksDoNotReplaceTheFirstResult() =
        runBlocking {
            val redirect = AndroidAuthorizationCallbackRegistry.register("com.example.app:/duplicate-callback")
            try {
                val first = "com.example.app:/duplicate-callback?code=first&state=one"
                deliverViaActivity(first)
                assertEquals(first, withTimeout(5_000) { redirect.await() })
                deliverViaActivity("com.example.app:/duplicate-callback?code=duplicate&state=two")
                assertEquals(first, redirect.await())
            } finally {
                AndroidAuthorizationCallbackRegistry.unregister(redirect)
            }
        }

    @Test
    fun oldActivityCallbackAndCleanupDoNotAffectAnotherRoute() =
        runBlocking {
            val old = AndroidAuthorizationCallbackRegistry.register("com.example.app:/old")
            val first = "com.example.app:/old?code=first"
            deliverViaActivity(first)
            assertEquals(first, withTimeout(5_000) { old.await() })
            val current = AndroidAuthorizationCallbackRegistry.register("com.example.app:/oauth/callback")
            try {
                AndroidAuthorizationCallbackRegistry.unregister(old)
                deliverViaActivity("com.example.app:/old?code=late")
                val expected = "com.example.app:/oauth/callback?code=current"
                deliverViaActivity(expected)
                assertEquals(expected, withTimeout(5_000) { current.await() })
            } finally {
                AndroidAuthorizationCallbackRegistry.unregister(old)
                AndroidAuthorizationCallbackRegistry.unregister(current)
            }
        }

    @Test
    fun matchingMalformedAndStaleActivityCallbacksFailCoreValidation() =
        runBlocking {
            val configuration =
                uniffi.appauth_rust.FfiServiceConfiguration(
                    "https://issuer.example/authorize",
                    "https://issuer.example/token",
                )
            try {
                val invalidQueries =
                    listOf(
                        "code=%GG",
                        "code=%FF",
                        "code=foreign&state=old-operation",
                        "code=value&state=one&state=two",
                    )
                for (query in invalidQueries) {
                    val session =
                        uniffi.appauth_rust.beginAuthorization(
                            configuration,
                            uniffi.appauth_rust.FfiAuthorizationOptions(
                                "client",
                                "com.example.app:/oauth/callback",
                                emptyList(),
                                emptyList(),
                                emptyList(),
                            ),
                            UrlConnectionNativeHttpTransport(),
                        )
                    val redirect = AndroidAuthorizationCallbackRegistry.register("com.example.app:/oauth/callback")
                    try {
                        val callback = "com.example.app:/oauth/callback?$query"
                        deliverViaActivity(callback)
                        val delivered = withTimeout(5_000) { redirect.await() }
                        assertThrows(uniffi.appauth_rust.FfiException.InvalidResponse::class.java) {
                            session.parseRedirect(delivered)
                        }
                    } finally {
                        AndroidAuthorizationCallbackRegistry.unregister(redirect)
                        session.close()
                    }
                }
            } finally {
                configuration.close()
            }
        }

    private fun deliverViaActivity(uri: String) {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        context.startActivity(
            Intent(context, AndroidAuthorizationCallbackActivity::class.java)
                .setAction(Intent.ACTION_VIEW)
                .setData(Uri.parse(uri))
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
        )
        instrumentation.waitForIdleSync()
    }

    private fun assertCallbackDelivered(
        redirectUri: String,
        callbackUri: String,
    ) = runBlocking {
        val redirect = AndroidAuthorizationCallbackRegistry.register(redirectUri)
        try {
            val context = InstrumentationRegistry.getInstrumentation().targetContext
            context.startActivity(
                Intent(Intent.ACTION_VIEW, Uri.parse(callbackUri))
                    .addCategory(Intent.CATEGORY_DEFAULT)
                    .addCategory(Intent.CATEGORY_BROWSABLE)
                    .setPackage(context.packageName)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            )

            assertEquals(callbackUri, withTimeout(5_000) { redirect.await() })
        } finally {
            AndroidAuthorizationCallbackRegistry.unregister(redirect)
        }
    }
}
