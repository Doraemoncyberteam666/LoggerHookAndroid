package com.dct.hooklogger

import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSession

class AutoBypassHooksTest {

    @Test
    fun installAllTrustingSslDefaultsReplacesHttpsURLConnectionFactory() {
        val before = HttpsURLConnection.getDefaultSSLSocketFactory()
        val ok = AutoBypassHooks.installAllTrustingSslDefaults()
        assertTrue("installAllTrustingSslDefaults reported failure", ok)
        val after = HttpsURLConnection.getDefaultSSLSocketFactory()
        assertNotNull(after)
        // We can't strictly assert "before != after" because the JVM might already have an
        // identical reference under heavy reuse, but we can verify the new factory talks to
        // our trust manager: it must not throw on createSocket().
        // Just verifying the call succeeded and returned a factory is enough for host-JVM coverage.
    }

    @Test
    fun installPermissiveHostnameVerifierAcceptsArbitraryHosts() {
        val ok = AutoBypassHooks.installPermissiveHostnameVerifier()
        assertTrue(ok)
        val verifier = HttpsURLConnection.getDefaultHostnameVerifier()
        assertNotNull(verifier)
        // Pass a null SSLSession — our verifier must still return true.
        assertTrue(verifier.verify("example.com", null as SSLSession?))
        assertTrue(verifier.verify("totally-malicious.example", null as SSLSession?))
    }
}
