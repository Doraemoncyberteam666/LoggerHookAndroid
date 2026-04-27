package com.dct.hooklogger

import java.security.cert.X509Certificate
import javax.net.ssl.SSLSession

/**
 * Drop-in helpers for bypassing TLS pinning / hostname verification when smali patching
 * a target app. None of these methods *enable* an MITM by themselves -- they replace the
 * decision points that the target app uses to reject a forged certificate.
 *
 * Smali patterns:
 *
 * ```smali
 * # Replace X509TrustManager.checkServerTrusted -> no-op:
 * invoke-static {p1, p2}, Lcom/dct/hooklogger/Hook;->acceptAllCheckServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
 *
 * # Replace HostnameVerifier.verify -> always true:
 * invoke-static {p0, p1}, Lcom/dct/hooklogger/Hook;->acceptAllHostnameVerifier(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z
 *
 * # Replace okhttp3.CertificatePinner.check (single-host variant):
 * invoke-static {p1, p2}, Lcom/dct/hooklogger/Hook;->fakePinnerSatisfied(Ljava/lang/String;Ljava/util/List;)V
 * ```
 */
internal object SSLBypassHooks {
    fun acceptAllCheckServerTrusted(chain: Array<X509Certificate>?, authType: String?) {
        val n = chain?.size ?: 0
        val subject = chain?.firstOrNull()?.subjectDN?.name ?: "<empty>"
        HookRuntime.write("SSL_BYPASS", "checkServerTrusted bypassed authType=${authType ?: "null"} chain=$n leaf='$subject'")
    }

    fun acceptAllCheckClientTrusted(chain: Array<X509Certificate>?, authType: String?) {
        val n = chain?.size ?: 0
        HookRuntime.write("SSL_BYPASS", "checkClientTrusted bypassed authType=${authType ?: "null"} chain=$n")
    }

    fun acceptAllHostnameVerifier(hostname: String?, session: SSLSession?): Boolean {
        val peer = session?.peerHost ?: "null"
        HookRuntime.write("SSL_BYPASS", "hostnameVerifier bypassed host='${hostname ?: "null"}' peer='$peer'")
        return true
    }

    fun fakePinnerSatisfied(hostname: String?, peerCertificates: List<*>?) {
        val n = peerCertificates?.size ?: 0
        HookRuntime.write("SSL_BYPASS", "okhttp3.CertificatePinner.check bypassed host='${hostname ?: "null"}' certs=$n")
    }

    /**
     * Variant for `CertificatePinner.check(host, vararg certs)` callers — Java vararg surface.
     */
    @JvmStatic
    fun fakePinnerSatisfiedVarargs(hostname: String?, vararg peerCertificates: Any?) {
        HookRuntime.write("SSL_BYPASS", "okhttp3.CertificatePinner.check (vararg) bypassed host='${hostname ?: "null"}' certs=${peerCertificates.size}")
    }

    /**
     * Replacement for Conscrypt's `RealTrustManager.checkServerTrusted` style methods that take
     * a `(chain, authType, host)` triple. Calling this is equivalent to "accept" without throwing.
     */
    fun acceptAllCheckServerTrustedHosted(
        chain: Array<X509Certificate>?,
        authType: String?,
        host: String?
    ) {
        val n = chain?.size ?: 0
        HookRuntime.write(
            "SSL_BYPASS",
            "Conscrypt-style checkServerTrusted bypassed host='${host ?: "null"}' authType=${authType ?: "null"} chain=$n"
        )
    }
}
