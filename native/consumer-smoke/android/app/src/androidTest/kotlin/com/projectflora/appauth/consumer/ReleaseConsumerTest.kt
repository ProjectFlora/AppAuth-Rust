package com.projectflora.appauth.consumer

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.appauth_rust.FfiServiceConfiguration

@RunWith(AndroidJUnit4::class)
class ReleaseConsumerTest {
    @Test
    fun constructsAndCallsThePublishedKotlinApi() {
        val configuration = FfiServiceConfiguration(
            "https://issuer.example/authorize",
            "https://issuer.example/token",
        )

        assertEquals("https://issuer.example/authorize", configuration.authorizationEndpoint())
        assertEquals("https://issuer.example/token", configuration.tokenEndpoint())
    }
}
