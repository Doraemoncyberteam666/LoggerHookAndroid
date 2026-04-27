# LoggerHookAndroid
Hook into any app and log its behavior.

Minimal Kotlin Android hook-runtime APK source.

## Build

```bash
./BUILD_WITH_SYSTEM_GRADLE.sh
```

APK output:

```bash
app/build/outputs/apk/debug/app-debug.apk
```

## Static smali-friendly methods

```smali
invoke-static {v0}, Lcom/dct/hooklogger/Hook;->log(Ljava/lang/String;)V
invoke-static {v0, v1}, Lcom/dct/hooklogger/Hook;->log(Ljava/lang/String;Ljava/lang/String;)V
invoke-static {v0, v1}, Lcom/dct/hooklogger/Hook;->kv(Ljava/lang/String;Ljava/lang/Object;)V
invoke-static {v0}, Lcom/dct/hooklogger/Hook;->trace(Ljava/lang/String;)V
invoke-static {v0}, Lcom/dct/hooklogger/Hook;->stack(Ljava/lang/String;)V
invoke-static {v0, v1}, Lcom/dct/hooklogger/Hook;->hex(Ljava/lang/String;[B)V
invoke-static {v0, v1}, Lcom/dct/hooklogger/Hook;->dumpObj(Ljava/lang/String;Ljava/lang/Object;)V
invoke-static {v0, v1}, Lcom/dct/hooklogger/Hook;->bundle(Ljava/lang/String;Landroid/os/Bundle;)V
invoke-static {}, Lcom/dct/hooklogger/Hook;->thread()V
invoke-static {v0}, Lcom/dct/hooklogger/Hook;->init(Landroid/content/Context;)V
invoke-static {}, Lcom/dct/hooklogger/Hook;->flush()V
invoke-static {v0}, Lcom/dct/hooklogger/Hook;->setLevel(Ljava/lang/String;)V
invoke-static {v0}, Lcom/dct/hooklogger/Hook;->setJsonOutput(Z)V
```

The full bypass surface (TLS, Frida/Xposed, Crypto, Network, Intent, Reflection)
is documented in the sections below.

## Bypassing Runtime Protections

This logger includes methods to help evade anti-tampering and runtime protections when reverse engineering:

1. **Disable Logcat Logging:**
   Some protections check `logcat` for tampering flags or hook standard Android logging. You can disable standard Logcat output and strictly write to the local file:
   ```smali
   invoke-static {}, Lcom/dct/hooklogger/Hook;->disableLogcat()V
   ```

2. **Prevent App Crash:**
   Some protections purposely throw uncaught exceptions to crash the app if they detect modifications. Suppress these:
   ```smali
   invoke-static {}, Lcom/dct/hooklogger/Hook;->suppressCrashes()V
   ```

3. **Bypass System.exit():**
   If an app tries to kill itself (e.g., `System.exit(0)`), find that Smali code and replace `invoke-static ..., Ljava/lang/System;->exit(I)V` with:
   ```smali
   invoke-static {v0}, Lcom/dct/hooklogger/Hook;->dummyExit(I)V
   ```

4. **Spoof Debugger Status:**
   Replace `invoke-static {}, Landroid/os/Debug;->isDebuggerConnected()Z` with:
   ```smali
   invoke-static {}, Lcom/dct/hooklogger/Hook;->fakeIsDebuggerConnected()Z
   ```
   Extended checks often also query Developer Options and USB debugging state via `Settings.Global`. You can bypass those probes too:
   ```smali
   # Replace getInt(..., "development_settings_enabled", ...)
   invoke-static {}, Lcom/dct/hooklogger/Hook;->fakeDevelopmentSettingsEnabled()I

   # Replace getInt(..., "adb_enabled", ...)
   invoke-static {}, Lcom/dct/hooklogger/Hook;->fakeAdbEnabled()I

   # Generic helper when original key/value is available:
   invoke-static {vKey, vOriginal}, Lcom/dct/hooklogger/Hook;->sanitizedGlobalSetting(Ljava/lang/String;I)I
   ```

5. **Spoof Installer Source:**
   Replace `invoke-virtual {pm, pkg}, Landroid/content/pm/PackageManager;->getInstallerPackageName(Ljava/lang/String;)Ljava/lang/String;` with:
   ```smali
   # IMPORTANT: pass the original package-name register (`pkg`), not the PackageManager register (`pm`).
   # If original args are {v2, v5} where v2=pm and v5=pkg, use v5 below:
   invoke-static {v5}, Lcom/dct/hooklogger/Hook;->fakeGetInstallerPackageName(Ljava/lang/String;)Ljava/lang/String;
   ```


6. **Bypass Root / Magisk / SU checks:**
   - For `Runtime.exec(Ljava/lang/String;)Ljava/lang/Process;`, sanitize **then** call `exec` (do not replace `exec` directly with this helper):
   ```smali
   invoke-static {v0}, Lcom/dct/hooklogger/Hook;->sanitizedRuntimeCommand(Ljava/lang/String;)Ljava/lang/String;
   move-result-object v0
   invoke-virtual {vRuntime, v0}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;
   ```
   - For `Runtime.exec([Ljava/lang/String;)Ljava/lang/Process;`, sanitize argv first and keep argument semantics:
   ```smali
   invoke-static {v0}, Lcom/dct/hooklogger/Hook;->sanitizedRuntimeCommandArgs([Ljava/lang/String;)[Ljava/lang/String;
   move-result-object v0
   invoke-virtual {vRuntime, v0}, Ljava/lang/Runtime;->exec([Ljava/lang/String;)Ljava/lang/Process;
   ```
   `sanitizedRuntimeCommand*` only swaps suspicious executable tokens (e.g. `su`) while preserving the original argument tail/vector.
   - Replace file existence probes like `/system/bin/su` with:
   ```smali
   invoke-static {v0}, Lcom/dct/hooklogger/Hook;->fakeFileExistsForRoot(Ljava/lang/String;)Z
   ```
   - Replace `/proc/mounts` string checks with:
   ```smali
   invoke-static {v0}, Lcom/dct/hooklogger/Hook;->sanitizedProcMounts(Ljava/lang/String;)Ljava/lang/String;
   ```
   - Replace `SystemProperties.get(...)` result handling with:
   ```smali
   invoke-static {v0, v1}, Lcom/dct/hooklogger/Hook;->sanitizedSystemProperty(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
   ```
   - Replace RootBeer/native detector boolean returns with:
   ```smali
   invoke-static {v0, v1}, Lcom/dct/hooklogger/Hook;->sanitizeRootBeerCheck(Ljava/lang/String;Z)Z
   ```

7. **Bypass Emulator / Virtual Device checks:**
   - Generic boolean emulator probes:
   ```smali
   invoke-static {v0, v1}, Lcom/dct/hooklogger/Hook;->sanitizeEmulatorCheck(Ljava/lang/String;Z)Z
   ```
   - Build/prop-based probes (`ro.hardware`, `ro.kernel.qemu`, `Build.FINGERPRINT`):
   ```smali
   invoke-static {v0}, Lcom/dct/hooklogger/Hook;->sanitizedHardware(Ljava/lang/String;)Ljava/lang/String;
   invoke-static {v0}, Lcom/dct/hooklogger/Hook;->sanitizedKernelQemu(Ljava/lang/String;)Ljava/lang/String;
   invoke-static {v0}, Lcom/dct/hooklogger/Hook;->sanitizedFingerprint(Ljava/lang/String;)Ljava/lang/String;
   ```
   - Telephony null/empty IMEI probes:
   ```smali
   invoke-static {v0}, Lcom/dct/hooklogger/Hook;->sanitizedImei(Ljava/lang/String;)Ljava/lang/String;
   ```
   - Sensor count and battery-level heuristics:
   ```smali
   invoke-static {v0}, Lcom/dct/hooklogger/Hook;->sanitizedSensorCount(I)I
   invoke-static {v0}, Lcom/dct/hooklogger/Hook;->sanitizedBatteryLevel(I)I
   ```

8. **Bypass TLS Pinning / Hostname Verification:**
   - Replace `X509TrustManager.checkServerTrusted([..], String)V`:
   ```smali
   invoke-static {p1, p2}, Lcom/dct/hooklogger/Hook;->acceptAllCheckServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
   ```
   - Replace the Conscrypt-style 3-arg variant `(chain, authType, host)`:
   ```smali
   invoke-static {p1, p2, p3}, Lcom/dct/hooklogger/Hook;->acceptAllCheckServerTrustedHosted([Ljava/security/cert/X509Certificate;Ljava/lang/String;Ljava/lang/String;)V
   ```
   - Replace `HostnameVerifier.verify` to always accept:
   ```smali
   invoke-static {p0, p1}, Lcom/dct/hooklogger/Hook;->acceptAllHostnameVerifier(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z
   move-result v0
   return v0
   ```
   - Replace `okhttp3.CertificatePinner.check`:
   ```smali
   invoke-static {p1, p2}, Lcom/dct/hooklogger/Hook;->fakePinnerSatisfied(Ljava/lang/String;Ljava/util/List;)V
   ```

9. **Bypass Frida / Xposed Detection:**
   - Sanitize `/proc/self/status` content used for `TracerPid` detection:
   ```smali
   invoke-static {v0}, Lcom/dct/hooklogger/Hook;->sanitizedTracerPidStatus(Ljava/lang/String;)Ljava/lang/String;
   ```
   - Strip Frida-listening rows from `/proc/net/tcp[6]` output:
   ```smali
   invoke-static {v0}, Lcom/dct/hooklogger/Hook;->sanitizedProcNetTcp(Ljava/lang/String;)Ljava/lang/String;
   ```
   - Strip frida/xposed/substrate lines from `/proc/self/maps` output:
   ```smali
   invoke-static {v0}, Lcom/dct/hooklogger/Hook;->sanitizedProcMaps(Ljava/lang/String;)Ljava/lang/String;
   ```
   - Filter known instrumentation libs out of a list returned by an enumerator:
   ```smali
   invoke-static {v0}, Lcom/dct/hooklogger/Hook;->sanitizedLoadedLibraries([Ljava/lang/String;)[Ljava/lang/String;
   ```
   - Force-`false` the boolean from a custom Frida probe:
   ```smali
   invoke-static {}, Lcom/dct/hooklogger/Hook;->fakeFridaListening()Z
   ```
   - Native variants that read the file from C++ (helpful when the Java path is
     monitored or when you want to use the included `libdcthook.so`):
   ```smali
   invoke-static {v0}, Lcom/dct/hooklogger/Hook;->nativeSanitizedStatusFile(Ljava/lang/String;)Ljava/lang/String;
   invoke-static {v0}, Lcom/dct/hooklogger/Hook;->nativeSanitizedProcNetTcp(Ljava/lang/String;)Ljava/lang/String;
   invoke-static {v0}, Lcom/dct/hooklogger/Hook;->isLibraryMapped(Ljava/lang/String;)Z
   ```

10. **Crypto / Network / Intent / Reflection Tap Points:**
    - Tap a `Cipher.doFinal(byte[])` call to log algorithm + IV + payload:
    ```smali
    invoke-static {v0, v1, v2}, Lcom/dct/hooklogger/Hook;->logCipher(Ljava/lang/String;Ljavax/crypto/Cipher;[B)V
    ```
    - Tap an HTTP request before it leaves the app:
    ```smali
    invoke-static {v0, v1, v2, v3}, Lcom/dct/hooklogger/Hook;->logHttpRequest(Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;[B)V
    ```
    - Tap a `startActivity`/`sendBroadcast` site to dump the intent:
    ```smali
    invoke-static {v0}, Lcom/dct/hooklogger/Hook;->logActivityStart(Landroid/content/Intent;)V
    ```
    - Smali-friendly reflection (no dex-time reference to private types):
    ```smali
    invoke-static {v0, v1, v2, v3}, Lcom/dct/hooklogger/Hook;->invokeStatic(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Class;[Ljava/lang/Object;)Ljava/lang/Object;
    ```

## Native helpers (`libdcthook.so`)

The APK ships a small JNI library (`arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64`)
that backs a few of the bypass paths. Each native call has a pure-Kotlin
fallback so the APK keeps working even when the `.so` cannot be loaded.

| Method on `Hook` | What it does |
| --- | --- |
| `nativeAvailable()` | `true` if `libdcthook.so` was loaded |
| `nativeVersion()` | Native build identifier |
| `nativeSanitizedStatusFile(path)` | Reads any `*/status` file and forces `TracerPid: 0` |
| `nativeSanitizedProcNetTcp(path)` | Reads `/proc/net/tcp[6]` and drops Frida-port rows |
| `isLibraryMapped(needle)` | Scans `/proc/self/maps` line-by-line for a substring |

## Runtime configuration

`HookConfig` exposes runtime knobs you can flip from smali via `Hook.setLevel`
/ `Hook.setJsonOutput` / `Hook.setMaxLogBytes`. You can also drop a properties
file at:

```text
<external files dir>/dct_hook.properties
```

Recognised keys:

```
level=VERBOSE|DEBUG|INFO|WARN|ERROR
tagFilter=STACK,DUMP
jsonOutput=true|false
useLogcat=true|false
maxLogBytes=5242880
rotationCount=3
queueCapacity=2048
```

The runtime now rotates the log file once it exceeds `maxLogBytes` (default
5 MiB), keeping `dct_hook.log.1`, `.2`, ... up to `rotationCount`. Set
`rotationCount=0` to truncate instead of rotating.

## Log location

Default log path after `Hook.init(context)`:

```text
/storage/emulated/0/Android/data/com.dct.hooklogger/files/dct_hook.log
```

When merged into another app, the package path becomes the host app package.

## Notes

- `getExternalFilesDir()` does not need runtime storage permission.
- Legacy storage permissions are included for old Android versions.
- All hook methods are `@JvmStatic` and crash-safe.
- Native helpers gracefully fall back to pure-Kotlin equivalents on ABIs where
  the bundled `.so` cannot be loaded.
