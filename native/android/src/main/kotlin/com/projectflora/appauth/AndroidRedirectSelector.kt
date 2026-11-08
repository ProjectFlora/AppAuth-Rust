package com.projectflora.appauth

import java.net.IDN
import java.net.URI
import java.net.URISyntaxException
import java.util.Locale

internal object AndroidRedirectSelector {
    fun select(
        redirects: AndroidRedirectConfiguration,
        isVerifiedAppLink: (URI) -> Boolean,
        resolvesToCallbackActivity: (URI) -> Boolean,
    ): String {
        val appLink =
            redirects.appLinkUri?.let {
                parse(it, "App Link").also { uri ->
                    if (!uri.scheme.equals("https", ignoreCase = true) || uri.host.isNullOrBlank()) {
                        throw AndroidAuthorizationAdapterException.InvalidRedirectConfiguration(
                            "The App Link redirect must use HTTPS and include a host",
                        )
                    }
                    if (uri.port != -1 && uri.port != 443) {
                        throw AndroidAuthorizationAdapterException.InvalidRedirectConfiguration(
                            "The App Link redirect must use port 443",
                        )
                    }
                }
            }
        val customScheme =
            redirects.customSchemeUri?.let {
                parse(it, "custom-scheme").also { uri ->
                    if (uri.scheme.isNullOrBlank() ||
                        uri.scheme.equals("http", ignoreCase = true) ||
                        uri.scheme.equals("https", ignoreCase = true) ||
                        uri.isOpaque
                    ) {
                        throw AndroidAuthorizationAdapterException.InvalidRedirectConfiguration(
                            "The fallback redirect must use a hierarchical custom URI scheme",
                        )
                    }
                }
            }

        if (appLink == null && customScheme == null) {
            throw AndroidAuthorizationAdapterException.InvalidRedirectConfiguration(
                "Configure an App Link, a custom-scheme redirect, or both",
            )
        }
        if (appLink != null &&
            isVerifiedAppLink(appLink) &&
            resolvesToCallbackActivity(appLink)
        ) {
            return appLink.toString()
        }
        if (customScheme != null && resolvesToCallbackActivity(customScheme)) {
            return customScheme.toString()
        }
        if (appLink != null) {
            throw AndroidAuthorizationAdapterException.InvalidRedirectConfiguration(
                "The App Link is not verified or its callback activity is not registered, and no registered custom-scheme fallback is available",
            )
        }
        throw AndroidAuthorizationAdapterException.CallbackActivityNotRegistered()
    }

    fun normalizedHost(host: String): String = IDN.toASCII(host).lowercase(Locale.ROOT)

    private fun parse(
        value: String,
        label: String,
    ): URI {
        val uri =
            try {
                URI(value)
            } catch (_: URISyntaxException) {
                throw AndroidAuthorizationAdapterException.InvalidRedirectConfiguration(
                    "The $label redirect URI is invalid",
                )
            }
        if (!uri.isAbsolute || uri.rawFragment != null || uri.rawUserInfo != null) {
            throw AndroidAuthorizationAdapterException.InvalidRedirectConfiguration(
                "The $label redirect URI must be absolute and cannot contain user information or a fragment",
            )
        }
        return uri
    }
}
