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
}
