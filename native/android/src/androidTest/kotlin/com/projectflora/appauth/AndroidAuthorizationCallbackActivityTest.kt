package com.projectflora.appauth

import android.content.Intent
import android.net.Uri
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
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
