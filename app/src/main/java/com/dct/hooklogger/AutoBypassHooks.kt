package com.dct.hooklogger

import android.content.Context
import android.os.Build
import java.lang.reflect.Field
import java.lang.reflect.Modifier
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * "Lockdown" mode — installs every bypass that can actually be applied at runtime
 * without bytecode instrumentation, in a single call.
 *
 * The smali-patch model still gives strictly better coverage (because instructions
 * baked into the host app cannot be opted-out at runtime), but `installAll` is the
 * convenience escape-hatch when you want a one-liner to dummy as much as possible.
 *
 * What it actually does at runtime:
 *
 * 1. `Hook.init(ctx)` — wires up the log file path + loads `dct_hook.properties`.
 * 2. `Hook.suppressCrashes()` — installs a default `UncaughtExceptionHandler`
 *    that swallows + logs unhandled exceptions.
 * 3. `Hook.disableLogcat()` (optional, controlled by `disableLogcat` flag) —
 *    routes all hook output to the file only.
 * 4. Spoofs the public `Build.*` fields that emulator/debugger detectors usually read
 *    (FINGERPRINT, HARDWARE, PRODUCT, MODEL, MANUFACTURER, BRAND, DEVICE, TAGS, TYPE).
 *    Done via reflection on `static final` fields, which works on Android.
 * 5. Replaces the JVM-default `SSLContext`, `SSLSocketFactory`, and
 *    `HostnameVerifier` with all-trusting ones. Apps that build their own SSL
 *    contexts still need the per-call-site smali patch; this only affects code
 *    that uses the JVM defaults.
 * 6. Pre-loads the bundled `libdcthook.so` so [NativeHook] short-circuits to
 *    its native fast paths.
 *
 * Returns a [Report] describing which steps succeeded so callers can log it.
 */
object AutoBypassHooks {

    data class Report(
        val initialized: Boolean,
        val crashesSuppressed: Boolean,
        val logcatDisabled: Boolean,
        val buildFieldsSpoofed: Int,
        val sslDefaultInstalled: Boolean,
        val hostnameVerifierInstalled: Boolean,
        val nativePreloaded: Boolean
    ) {
        override fun toString(): String =
            "AutoBypass[init=$initialized,crashes=$crashesSuppressed,logcat=$logcatDisabled," +
                "build=$buildFieldsSpoofed,ssl=$sslDefaultInstalled,host=$hostnameVerifierInstalled,native=$nativePreloaded]"
    }

    /**
     * One-shot installer. Safe to call more than once.
     *
     * @param context    the host app context (or any context — `applicationContext` is taken).
     * @param disableLogcat strip Logcat output and write only to the file.
     * @param spoofBuildFields rewrite `android.os.Build` fields to look like a stock retail device.
     * @param installSslDefaults install all-trusting JVM-default SSL pieces.
     */
    @JvmOverloads
    fun installAll(
        context: Context?,
        disableLogcat: Boolean = false,
        spoofBuildFields: Boolean = true,
        installSslDefaults: Boolean = true
    ): Report {
        val initialized = HookRuntime.runCatchingForJni("autoBypass.init") {
            ProtectionHooks.init(context)
            true
        } ?: false

        val crashesSuppressed = HookRuntime.runCatchingForJni("autoBypass.crashes") {
            ProtectionHooks.suppressCrashes()
            true
        } ?: false

        val logcatDisabled = if (disableLogcat) {
            HookRuntime.runCatchingForJni("autoBypass.logcat") {
                ProtectionHooks.disableLogcat()
                true
            } ?: false
        } else false

        val buildFieldsSpoofed = if (spoofBuildFields) spoofBuildFields() else 0

        val sslDefaultInstalled = if (installSslDefaults) installAllTrustingSslDefaults() else false
        val hostnameVerifierInstalled = if (installSslDefaults) installPermissiveHostnameVerifier() else false

        val nativePreloaded = NativeHook.isAvailable()

        val report = Report(
            initialized,
            crashesSuppressed,
            logcatDisabled,
            buildFieldsSpoofed,
            sslDefaultInstalled,
            hostnameVerifierInstalled,
            nativePreloaded
        )
        HookRuntime.write("AUTO_BYPASS", report.toString())
        return report
    }

    /**
     * Returns the number of [Build] fields it managed to overwrite. The values are
     * routed through [EmulatorBypassHooks] sanitizers so the chosen "clean" values stay
     * consistent with the per-call-site overrides.
     */
    @JvmStatic
    fun spoofBuildFields(): Int {
        val pairs: List<Pair<String, String>> = listOf(
            "FINGERPRINT" to EmulatorBypassHooks.sanitizedFingerprint(safeBuildString("FINGERPRINT")),
            "HARDWARE" to EmulatorBypassHooks.sanitizedHardware(safeBuildString("HARDWARE")),
            "PRODUCT" to "redfin",
            "MODEL" to "Pixel 5",
            "MANUFACTURER" to "Google",
            "BRAND" to "google",
            "DEVICE" to "redfin",
            "BOARD" to "redfin",
            "TAGS" to "release-keys",
            "TYPE" to "user",
            "BOOTLOADER" to "redfin-1.0-7942283",
            "HOST" to "abfarm-release"
        )

        var ok = 0
        for ((field, value) in pairs) {
            if (setBuildString(field, value)) ok += 1
        }
        HookRuntime.write("AUTO_BYPASS", "spoofBuildFields wrote $ok of ${pairs.size} Build fields")
        return ok
    }

    /**
     * Replaces [SSLContext.getDefault] and [HttpsURLConnection.setDefaultSSLSocketFactory]
     * with an all-trusting context. Caller code that uses the JVM defaults (very common
     * for `HttpURLConnection`-based clients) will then accept any server cert.
     *
     * Code that builds its own `SSLContext` / `OkHttpClient` / etc. is unaffected — you
     * still need the per-call-site smali patch ([SSLBypassHooks]) for those.
     */
    @JvmStatic
    fun installAllTrustingSslDefaults(): Boolean {
        return HookRuntime.runCatchingForJni("autoBypass.ssl") {
            val tm = arrayOf<TrustManager>(object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?) {
                    HookRuntime.write("SSL_BYPASS", "default checkClientTrusted bypassed (authType=${authType ?: "null"})")
                }
                override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) {
                    HookRuntime.write("SSL_BYPASS", "default checkServerTrusted bypassed (authType=${authType ?: "null"}, chain=${chain?.size ?: 0})")
                }
                override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            })
            val ctx = SSLContext.getInstance("TLS")
            ctx.init(null, tm, SecureRandom())
            HttpsURLConnection.setDefaultSSLSocketFactory(ctx.socketFactory)
            // Also set as the JVM default so libraries using SSLContext.getDefault() pick it up.
            try {
                SSLContext.setDefault(ctx)
            } catch (_: Throwable) {
                // Some VMs disallow overriding the default — that's fine, the HttpsURLConnection
                // socket factory above is the more impactful piece.
            }
            HookRuntime.write("SSL_BYPASS", "all-trusting default SSLContext + HttpsURLConnection socket factory installed")
            true
        } ?: false
    }

    @JvmStatic
    fun installPermissiveHostnameVerifier(): Boolean {
        return HookRuntime.runCatchingForJni("autoBypass.hostname") {
            HttpsURLConnection.setDefaultHostnameVerifier(HostnameVerifier { hostname, _ ->
                HookRuntime.write("SSL_BYPASS", "default HostnameVerifier accepted hostname=${hostname ?: "null"}")
                true
            })
            true
        } ?: false
    }

    // ---------------- internals ----------------

    private fun safeBuildString(name: String): String {
        return try {
            val f = Build::class.java.getField(name)
            f.get(null) as? String ?: ""
        } catch (_: Throwable) {
            ""
        }
    }

    /**
     * Forcibly replaces `Build.<name>` with [value]. Returns true on success.
     *
     * `android.os.Build` exposes its values as `public static final String` — but on
     * Android Runtime (ART) `Field.set` succeeds against a final field as long as
     * accessibility is enabled.  We still strip the FINAL bit defensively.
     */
    private fun setBuildString(name: String, value: String): Boolean {
        return try {
            val field: Field = Build::class.java.getField(name)
            field.isAccessible = true
            try {
                val mods = Field::class.java.getDeclaredField("modifiers")
                mods.isAccessible = true
                mods.setInt(field, field.modifiers and Modifier.FINAL.inv())
            } catch (_: Throwable) {
                // Newer Android versions hide `modifiers` — Field.set on android.os.Build
                // still works without the strip on stock ART, so we keep going.
            }
            field.set(null, value)
            HookRuntime.write("AUTO_BYPASS", "Build.$name -> $value")
            true
        } catch (t: Throwable) {
            HookRuntime.write("AUTO_BYPASS", "Build.$name override failed: ${t.javaClass.name}: ${t.message}")
            false
        }
    }
}
