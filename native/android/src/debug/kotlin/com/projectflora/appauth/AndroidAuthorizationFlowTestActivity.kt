package com.projectflora.appauth

import android.app.Activity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import uniffi.appauth_rust.FfiAuthenticationState
import uniffi.appauth_rust.FfiAuthorizationOptions
import uniffi.appauth_rust.FfiServiceConfiguration
import uniffi.appauth_rust.NativeHttpTransport

class AndroidAuthorizationFlowTestActivity : Activity() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    fun authorize(
        configuration: FfiServiceConfiguration,
        options: FfiAuthorizationOptions,
        redirects: AndroidRedirectConfiguration,
        transport: NativeHttpTransport,
        onResult: (Result<FfiAuthenticationState>) -> Unit,
    ) {
        scope.launch {
            val result: Result<FfiAuthenticationState> =
                try {
                    Result.success(
                        AndroidAuthorizationAdapter(this@AndroidAuthorizationFlowTestActivity)
                            .authorize(configuration, options, redirects, transport),
                    )
                } catch (error: Exception) {
                    Result.failure(error)
                }
            onResult(result)
        }
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }
}
