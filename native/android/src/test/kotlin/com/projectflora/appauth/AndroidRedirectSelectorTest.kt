package com.projectflora.appauth

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidRedirectSelectorTest {
    @Test
    fun verifiedAppLinkIsPreferred() {
        val selected =
            AndroidRedirectSelector.select(
                redirects =
                    AndroidRedirectConfiguration(
                        appLinkUri = "https://login.example.com/oauth/callback",
                        customSchemeUri = "com.example.app:/oauth/callback",
                    ),
                isVerifiedAppLink = { true },
                resolvesToCallbackActivity = { true },
            )

        assertEquals("https://login.example.com/oauth/callback", selected)
    }

    @Test
    fun customSchemeIsUsedWhenAppLinkIsNotVerified() {
        val selected =
            AndroidRedirectSelector.select(
                redirects =
                    AndroidRedirectConfiguration(
                        appLinkUri = "https://login.example.com/oauth/callback",
                        customSchemeUri = "com.example.app:/oauth/callback",
                    ),
                isVerifiedAppLink = { false },
                resolvesToCallbackActivity = { uri ->
                    uri.scheme == "com.example.app"
                },
            )

        assertEquals("com.example.app:/oauth/callback", selected)
    }

    @Test
    fun unverifiedAppLinkWithoutRegisteredFallbackFailsExplicitly() {
        assertThrows(AndroidAuthorizationAdapterException.InvalidRedirectConfiguration::class.java) {
            AndroidRedirectSelector.select(
                redirects =
                    AndroidRedirectConfiguration(
                        appLinkUri = "https://login.example.com/oauth/callback",
                        customSchemeUri = null,
                    ),
                isVerifiedAppLink = { false },
                resolvesToCallbackActivity = { false },
            )
        }
    }

    @Test
    fun redirectTargetIgnoresResponseQueryButRequiresExactRoute() {
        val expected =
            RedirectTarget.parse(
                "https://login.example.com:443/oauth/callback?registered=value",
            )
        val actual =
            RedirectTarget.parse(
                "https://LOGIN.example.com/oauth/callback?code=abc&state=xyz",
            )
        val wrongPath = RedirectTarget.parse("https://login.example.com/oauth/other")

        assertTrue(expected!!.matches(actual!!))
        assertFalse(expected.matches(wrongPath!!))
    }

    @Test
    fun callbackRegistryIgnoresOtherRoutesAndDeliversTheMatchingCallback() =
        runBlocking {
            val redirect =
                AndroidAuthorizationCallbackRegistry.register(
                    "com.example.app:/oauth/callback",
                )
            try {
                AndroidAuthorizationCallbackRegistry.deliver("com.example.app:/other?code=ignored")
                assertFalse(redirect.isCompleted)

                val callback = "com.example.app:/oauth/callback?code=auth-code&state=state"
                AndroidAuthorizationCallbackRegistry.deliver(callback)

                assertTrue(redirect.isCompleted)
                assertEquals(callback, redirect.await())
            } finally {
                AndroidAuthorizationCallbackRegistry.unregister(redirect)
            }
        }

    @Test
    fun registryRejectsConcurrentRegistrationAndIgnoresDuplicateDelivery() =
        runBlocking {
            val redirect = AndroidAuthorizationCallbackRegistry.register("com.example.app:/callback")
            try {
                assertThrows(AndroidAuthorizationAdapterException.AuthorizationAlreadyRunning::class.java) {
                    AndroidAuthorizationCallbackRegistry.register("com.example.app:/callback")
                }
                val first = "com.example.app:/callback?code=first&state=one"
                AndroidAuthorizationCallbackRegistry.deliver(first)
                AndroidAuthorizationCallbackRegistry.deliver("com.example.app:/callback?code=second&state=two")
                assertEquals(first, redirect.await())
            } finally {
                AndroidAuthorizationCallbackRegistry.unregister(redirect)
            }
        }

    @Test
    fun staleCleanupCannotUnregisterTheNextOperation() =
        runBlocking {
            val old = AndroidAuthorizationCallbackRegistry.register("com.example.app:/old")
            AndroidAuthorizationCallbackRegistry.deliver("com.example.app:/old?code=old")
            val current = AndroidAuthorizationCallbackRegistry.register("com.example.app:/current")
            try {
                AndroidAuthorizationCallbackRegistry.unregister(old)
                AndroidAuthorizationCallbackRegistry.deliver("com.example.app:/old?code=stale")
                assertFalse(current.isCompleted)
                val callback = "com.example.app:/current?code=current"
                AndroidAuthorizationCallbackRegistry.deliver(callback)
                assertEquals(callback, current.await())
            } finally {
                AndroidAuthorizationCallbackRegistry.unregister(old)
                AndroidAuthorizationCallbackRegistry.unregister(current)
            }
        }

    @Test
    fun cancellationAndUnregisterAllowTheNextRegistration() =
        runBlocking {
            val old = AndroidAuthorizationCallbackRegistry.register("com.example.app:/callback")
            try {
                old.cancel()
                try {
                    old.await()
                    throw AssertionError("cancelled callback returned a value")
                } catch (_: uniffi.appauth_rust.FfiException.Cancelled) {
                }
            } finally {
                AndroidAuthorizationCallbackRegistry.unregister(old)
            }
            val current = AndroidAuthorizationCallbackRegistry.register("com.example.app:/callback")
            try {
                assertFalse(current.isCompleted)
            } finally {
                AndroidAuthorizationCallbackRegistry.unregister(current)
            }
        }

    @Test
    fun matchingMalformedCallbacksReachCoreValidation() =
        runBlocking {
            for (suffix in listOf("?code=%GG", "?code=%FF", "?code=value#fragment", "?code=value&state=old-operation")) {
                val redirect = AndroidAuthorizationCallbackRegistry.register("com.example.app:/callback")
                try {
                    val callback = "com.example.app:/callback$suffix"
                    AndroidAuthorizationCallbackRegistry.deliver(callback)
                    assertTrue(redirect.isCompleted)
                    assertEquals(callback, redirect.await())
                } finally {
                    AndroidAuthorizationCallbackRegistry.unregister(redirect)
                }
            }
        }

    @Test
    fun concurrentDeliveriesCompleteOnlyOnce() =
        runBlocking {
            val redirect = AndroidAuthorizationCallbackRegistry.register("com.example.app:/callback")
            try {
                val start = java.util.concurrent.CountDownLatch(1)
                val callbacks = listOf("com.example.app:/callback?code=one", "com.example.app:/callback?code=two")
                val workers =
                    callbacks.map { callback ->
                        Thread {
                            start.await()
                            AndroidAuthorizationCallbackRegistry.deliver(callback)
                        }.apply { start() }
                    }
                start.countDown()
                workers.forEach {
                    it.join(5_000)
                    assertFalse(it.isAlive)
                }
                assertTrue(callbacks.contains(redirect.await()))
            } finally {
                AndroidAuthorizationCallbackRegistry.unregister(redirect)
            }
        }
}
