package com.dct.hooklogger

import android.content.Context
import android.content.Intent
import android.os.Bundle
import java.security.Key
import java.security.cert.X509Certificate
import javax.crypto.Cipher
import javax.crypto.Mac
import java.security.MessageDigest
import javax.net.ssl.SSLSession

/**
 * Static-friendly hook runtime.
 *
 * All public methods are `@JvmStatic` so smali patches can call them with a single
 * `invoke-static` instruction.
 */
object Hook {
    @JvmStatic
    fun init(context: Context?) = ProtectionHooks.init(context)

    @JvmStatic
    fun flush() = HookRuntime.flush()

    // ---------------- Configuration ----------------

    @JvmStatic
    fun setLevel(level: String?) {
        HookConfig.level = HookConfig.Level.parse(level)
    }

    @JvmStatic
    fun setJsonOutput(enabled: Boolean) {
        HookConfig.jsonOutput = enabled
    }

    @JvmStatic
    fun setMaxLogBytes(bytes: Long) {
        HookConfig.maxLogBytes = bytes.coerceAtLeast(1024L)
    }

    @JvmStatic
    fun setRotationCount(count: Int) {
        HookConfig.rotationCount = count.coerceIn(0, 32)
    }

    @JvmStatic
    fun suppressTag(tag: String) = HookConfig.suppressTag(tag)

    @JvmStatic
    fun clearSuppressedTags() = HookConfig.clearSuppressedTags()

    // ---------------- Protection ----------------

    @JvmStatic
    fun disableLogcat() = ProtectionHooks.disableLogcat()

    @JvmStatic
    fun suppressCrashes() = ProtectionHooks.suppressCrashes()

    @JvmStatic
    fun dummyExit(status: Int) = ProtectionHooks.dummyExit(status)

    @JvmStatic
    fun fakeIsDebuggerConnected(): Boolean = ProtectionHooks.fakeIsDebuggerConnected()

    @JvmStatic
    fun fakeWaitingForDebugger(): Boolean = ProtectionHooks.fakeWaitingForDebugger()

    @JvmStatic
    fun fakeIsUserAMonkey(): Boolean = ProtectionHooks.fakeIsUserAMonkey()

    @JvmStatic
    fun fakeDevelopmentSettingsEnabled(): Int = ProtectionHooks.fakeDevelopmentSettingsEnabled()

    @JvmStatic
    fun fakeAdbEnabled(): Int = ProtectionHooks.fakeAdbEnabled()

    @JvmStatic
    fun sanitizedGlobalSetting(name: String?, originalValue: Int): Int =
        ProtectionHooks.sanitizedGlobalSetting(name, originalValue)

    @JvmStatic
    fun sanitizedBuildTags(): String = ProtectionHooks.sanitizedBuildTags()

    @JvmStatic
    fun sanitizedBuildType(): String = ProtectionHooks.sanitizedBuildType()

    @JvmStatic
    fun fakeRoDebuggable(): String = ProtectionHooks.fakeRoDebuggable()

    @JvmStatic
    fun fakeGetInstallerPackageName(packageName: String?): String? =
        ProtectionHooks.fakeGetInstallerPackageName(packageName)

    // ---------------- Root bypass ----------------

    @JvmStatic
    fun sanitizedRuntimeCommand(command: String?): String = RootBypassHooks.sanitizedRuntimeCommand(command)

    @JvmStatic
    fun sanitizedRuntimeCommandArgs(command: Array<String>?): Array<String> =
        RootBypassHooks.sanitizedRuntimeCommandArgs(command)

    @JvmStatic
    fun fakeFileExistsForRoot(path: String?): Boolean = RootBypassHooks.fakeFileExistsForRoot(path)

    @JvmStatic
    fun sanitizedProcMounts(content: String?): String = RootBypassHooks.sanitizedProcMounts(content)

    @JvmStatic
    fun sanitizedSystemProperty(key: String?, originalValue: String?): String =
        RootBypassHooks.sanitizedSystemProperty(key, originalValue)

    @JvmStatic
    fun sanitizeRootBeerCheck(checkName: String?, detected: Boolean): Boolean =
        RootBypassHooks.sanitizeRootBeerCheck(checkName, detected)

    // ---------------- Emulator bypass ----------------

    @JvmStatic
    fun sanitizeEmulatorCheck(checkName: String?, detected: Boolean): Boolean =
        EmulatorBypassHooks.sanitizeEmulatorCheck(checkName, detected)

    @JvmStatic
    fun sanitizedHardware(original: String?): String = EmulatorBypassHooks.sanitizedHardware(original)

    @JvmStatic
    fun sanitizedKernelQemu(original: String?): String = EmulatorBypassHooks.sanitizedKernelQemu(original)

    @JvmStatic
    fun sanitizedFingerprint(original: String?): String = EmulatorBypassHooks.sanitizedFingerprint(original)

    @JvmStatic
    fun sanitizedImei(original: String?): String = EmulatorBypassHooks.sanitizedImei(original)

    @JvmStatic
    fun sanitizedSensorCount(originalCount: Int): Int = EmulatorBypassHooks.sanitizedSensorCount(originalCount)

    @JvmStatic
    fun sanitizedBatteryLevel(originalPercent: Int): Int = EmulatorBypassHooks.sanitizedBatteryLevel(originalPercent)

    // ---------------- SSL bypass ----------------

    @JvmStatic
    fun acceptAllCheckServerTrusted(chain: Array<X509Certificate>?, authType: String?) =
        SSLBypassHooks.acceptAllCheckServerTrusted(chain, authType)

    @JvmStatic
    fun acceptAllCheckClientTrusted(chain: Array<X509Certificate>?, authType: String?) =
        SSLBypassHooks.acceptAllCheckClientTrusted(chain, authType)

    @JvmStatic
    fun acceptAllCheckServerTrustedHosted(
        chain: Array<X509Certificate>?,
        authType: String?,
        host: String?
    ) = SSLBypassHooks.acceptAllCheckServerTrustedHosted(chain, authType, host)

    @JvmStatic
    fun acceptAllHostnameVerifier(hostname: String?, session: SSLSession?): Boolean =
        SSLBypassHooks.acceptAllHostnameVerifier(hostname, session)

    @JvmStatic
    fun fakePinnerSatisfied(hostname: String?, peerCertificates: List<*>?) =
        SSLBypassHooks.fakePinnerSatisfied(hostname, peerCertificates)

    @JvmStatic
    fun fakePinnerSatisfiedVarargs(hostname: String?, vararg peerCertificates: Any?) =
        SSLBypassHooks.fakePinnerSatisfiedVarargs(hostname, *peerCertificates)

    // ---------------- Anti-analysis ----------------

    @JvmStatic
    fun sanitizedTracerPidStatus(content: String?): String =
        AntiAnalysisHooks.sanitizedTracerPidStatus(content)

    @JvmStatic
    fun sanitizedProcNetTcp(content: String?): String =
        AntiAnalysisHooks.sanitizedProcNetTcp(content)

    @JvmStatic
    fun sanitizedProcMaps(content: String?): String =
        AntiAnalysisHooks.sanitizedProcMaps(content)

    @JvmStatic
    fun sanitizedLoadedLibraries(libraries: Array<String>?): Array<String> =
        AntiAnalysisHooks.sanitizedLoadedLibraries(libraries)

    @JvmStatic
    fun fakeFridaListening(): Boolean = AntiAnalysisHooks.fakeFridaListening()

    @JvmStatic
    fun loggedLoadLibrary(name: String?): String? = AntiAnalysisHooks.loggedLoadLibrary(name)

    @JvmStatic
    fun loggedLoad(filename: String?): String? = AntiAnalysisHooks.loggedLoad(filename)

    // ---------------- Native bridge ----------------

    @JvmStatic
    fun nativeAvailable(): Boolean = NativeHook.isAvailable()

    @JvmStatic
    fun nativeVersion(): String = NativeHook.version()

    @JvmStatic
    fun nativeSanitizedStatusFile(path: String?): String = NativeHook.sanitizedStatusFile(path)

    @JvmStatic
    fun nativeSanitizedProcNetTcp(path: String?): String = NativeHook.sanitizedProcNetTcp(path)

    @JvmStatic
    fun isLibraryMapped(needle: String?): Boolean = NativeHook.isLibraryMapped(needle)

    // ---------------- Crypto ----------------

    @JvmStatic
    fun logCipher(label: String?, cipher: Cipher?, input: ByteArray?) =
        CryptoHooks.logCipher(label, cipher, input)

    @JvmStatic
    fun logCipher(label: String?, cipher: Cipher?, input: ByteArray?, output: ByteArray?) =
        CryptoHooks.logCipher(label, cipher, input, output)

    @JvmStatic
    fun logMessageDigest(label: String?, digest: MessageDigest?, input: ByteArray?, output: ByteArray?) =
        CryptoHooks.logMessageDigest(label, digest, input, output)

    @JvmStatic
    fun logMac(label: String?, mac: Mac?, input: ByteArray?, output: ByteArray?) =
        CryptoHooks.logMac(label, mac, input, output)

    @JvmStatic
    fun logKey(label: String?, key: Key?) = CryptoHooks.logKey(label, key)

    // ---------------- Network ----------------

    @JvmStatic
    fun logHttpRequest(method: String?, url: String?, headers: Map<String, String>?, body: ByteArray?) =
        NetworkHooks.logHttpRequest(method, url, headers, body)

    @JvmStatic
    fun logHttpResponse(code: Int, headers: Map<String, String>?, body: ByteArray?) =
        NetworkHooks.logHttpResponse(code, headers, body)

    @JvmStatic
    fun logUrl(label: String?, url: String?) = NetworkHooks.logUrl(label, url)

    @JvmStatic
    fun logWebSocket(direction: String?, payload: ByteArray?) = NetworkHooks.logWebSocket(direction, payload)

    // ---------------- Intents ----------------

    @JvmStatic
    fun logIntent(label: String?, intent: Intent?) = IntentHooks.logIntent(label, intent)

    @JvmStatic
    fun logActivityStart(intent: Intent?) = IntentHooks.logActivityStart(intent)

    @JvmStatic
    fun logService(intent: Intent?) = IntentHooks.logService(intent)

    @JvmStatic
    fun logBroadcast(intent: Intent?) = IntentHooks.logBroadcast(intent)

    // ---------------- Reflection ----------------

    @JvmStatic
    fun invokeStatic(className: String?, methodName: String?, sig: Array<Class<*>>?, args: Array<Any?>?): Any? =
        ReflectionHooks.invokeStatic(className, methodName, sig, args)

    @JvmStatic
    fun invokeVirtual(target: Any?, methodName: String?, sig: Array<Class<*>>?, args: Array<Any?>?): Any? =
        ReflectionHooks.invokeVirtual(target, methodName, sig, args)

    @JvmStatic
    fun getField(target: Any?, fieldName: String?): Any? = ReflectionHooks.getField(target, fieldName)

    @JvmStatic
    fun setField(target: Any?, fieldName: String?, value: Any?) = ReflectionHooks.setField(target, fieldName, value)

    @JvmStatic
    fun getStaticField(className: String?, fieldName: String?): Any? = ReflectionHooks.getStaticField(className, fieldName)

    @JvmStatic
    fun setStaticField(className: String?, fieldName: String?, value: Any?) = ReflectionHooks.setStaticField(className, fieldName, value)

    // ---------------- Logging ----------------

    @JvmStatic
    fun log(message: String?) = LoggingHooks.log(message)

    @JvmStatic
    fun log(tag: String?, message: String?) = LoggingHooks.log(tag, message)

    @JvmStatic
    fun kv(key: String?, value: Any?) = LoggingHooks.kv(key, value)

    @JvmStatic
    fun trace(method: String?) = LoggingHooks.trace(method)

    @JvmStatic
    fun stack(label: String?) = LoggingHooks.stack(label)

    @JvmStatic
    fun hex(label: String?, bytes: ByteArray?) = LoggingHooks.hex(label, bytes)

    @JvmStatic
    fun dumpObj(label: String?, obj: Any?) = LoggingHooks.dumpObj(label, obj)

    @JvmStatic
    fun bundle(label: String?, bundle: Bundle?) = LoggingHooks.bundle(label, bundle)

    @JvmStatic
    fun thread() = LoggingHooks.thread()

    @JvmStatic
    fun logPath(): String = LoggingHooks.logPath()

    @JvmStatic
    fun clear() = LoggingHooks.clear()

    // ---------------- Auto bypass ("lockdown" mode) ----------------

    /**
     * Single-call "install everything that can be installed at runtime" mode.
     *
     * Smali equivalents:
     *
     * ```smali
     * invoke-static {p0}, Lcom/dct/hooklogger/Hook;->autoBypassAll(Landroid/content/Context;)V
     *
     * # Or with options (disableLogcat, spoofBuildFields, installSslDefaults):
     * invoke-static {p0, v1, v2, v3}, Lcom/dct/hooklogger/Hook;->autoBypassAll(Landroid/content/Context;ZZZ)V
     * ```
     *
     * See [AutoBypassHooks] for the full list of bypasses applied.
     */
    @JvmStatic
    fun autoBypassAll(context: Context?) {
        AutoBypassHooks.installAll(context)
    }

    @JvmStatic
    fun autoBypassAll(
        context: Context?,
        disableLogcat: Boolean,
        spoofBuildFields: Boolean,
        installSslDefaults: Boolean
    ) {
        AutoBypassHooks.installAll(context, disableLogcat, spoofBuildFields, installSslDefaults)
    }

    /** Alias for [autoBypassAll] with [disableLogcat]=true and the rest enabled. */
    @JvmStatic
    fun lockdown(context: Context?) {
        AutoBypassHooks.installAll(
            context,
            disableLogcat = true,
            spoofBuildFields = true,
            installSslDefaults = true
        )
    }

    @JvmStatic
    fun spoofBuildFields(): Int = AutoBypassHooks.spoofBuildFields()

    @JvmStatic
    fun installAllTrustingSslDefaults(): Boolean = AutoBypassHooks.installAllTrustingSslDefaults()

    @JvmStatic
    fun installPermissiveHostnameVerifier(): Boolean = AutoBypassHooks.installPermissiveHostnameVerifier()
}
