package com.dct.hooklogger

/**
 * JNI bridge to `libdcthook.so`. Every call falls back to a pure-Kotlin equivalent if the
 * native library isn't available (e.g. on host JVM unit tests, or unsupported ABIs).
 *
 * Why native? A few of the bypass paths benefit from being callable without going through the
 * JVM I/O stack:
 *  - `appendLogLine` writes via `O_APPEND`/`write()` syscalls so a process under aggressive
 *    Java I/O monitoring still leaves a trace.
 *  - `sanitizedStatusFile` and `sanitizedProcNetTcp` run the whole replacement in C++ so the
 *    sanitized buffer never round-trips to Java memory before the result is needed.
 *  - `isLibraryMapped` scans `/proc/self/maps` line-by-line without allocating a giant String.
 */
object NativeHook {
    @Volatile
    private var loaded: Boolean = false

    init {
        loaded = try {
            System.loadLibrary("dcthook")
            true
        } catch (_: Throwable) {
            false
        }
    }

    @JvmStatic
    fun isAvailable(): Boolean = loaded

    @JvmStatic
    fun version(): String = if (loaded) safeNativeVersion() else "unavailable"

    /**
     * Reads `/proc/self/status` (or any path the caller specifies) and returns the contents
     * with `TracerPid:` rewritten to `0`. On native failure, falls back to the pure-Kotlin
     * sanitizer so callers still get a usable result.
     */
    @JvmStatic
    fun sanitizedStatusFile(path: String?): String {
        if (loaded && path != null) {
            try {
                return nativeSanitizedStatusFile(path) ?: ""
            } catch (_: Throwable) {
                // fall through
            }
        }
        val raw = readFileSafely(path)
        return AntiAnalysisHooks.sanitizedTracerPidStatus(raw)
    }

    /**
     * Reads `/proc/net/tcp` (or `/proc/net/tcp6`) and drops rows whose port columns match the
     * Frida block list.
     */
    @JvmStatic
    fun sanitizedProcNetTcp(path: String?): String {
        if (loaded && path != null) {
            try {
                return nativeSanitizedProcNetTcp(path) ?: ""
            } catch (_: Throwable) {
                // fall through
            }
        }
        val raw = readFileSafely(path)
        return AntiAnalysisHooks.sanitizedProcNetTcp(raw)
    }

    /**
     * Returns true if `/proc/self/maps` contains a substring matching [needle]
     * (case-insensitive). Always returns false when [needle] is null/blank.
     */
    @JvmStatic
    fun isLibraryMapped(needle: String?): Boolean {
        if (needle.isNullOrBlank()) return false
        return if (loaded) {
            try {
                nativeIsLibraryMapped(needle)
            } catch (_: Throwable) {
                fallbackIsLibraryMapped(needle)
            }
        } else {
            fallbackIsLibraryMapped(needle)
        }
    }

    /**
     * Append a single newline-terminated line directly to a log file using POSIX I/O.
     * Returns the number of bytes written (or -1 on failure / when native is unavailable).
     */
    @JvmStatic
    fun appendLogLine(path: String?, line: String?): Int {
        if (path.isNullOrEmpty() || line == null) return -1
        if (!loaded) return -1
        return try {
            nativeAppendLogLine(path, line)
        } catch (_: Throwable) {
            -1
        }
    }

    private fun safeNativeVersion(): String =
        try { nativeVersionImpl() ?: "unknown" } catch (_: Throwable) { "unknown" }

    private fun readFileSafely(path: String?): String {
        if (path.isNullOrBlank()) return ""
        return try {
            java.io.File(path).readText()
        } catch (_: Throwable) {
            ""
        }
    }

    private fun fallbackIsLibraryMapped(needle: String): Boolean {
        return try {
            val mapsLines = java.io.File("/proc/self/maps").readLines()
            val lower = needle.lowercase(java.util.Locale.US)
            mapsLines.any { it.lowercase(java.util.Locale.US).contains(lower) }
        } catch (_: Throwable) {
            false
        }
    }

    @JvmStatic private external fun nativeVersionImpl(): String?
    @JvmStatic private external fun nativeSanitizedStatusFile(path: String): String?
    @JvmStatic private external fun nativeSanitizedProcNetTcp(path: String): String?
    @JvmStatic private external fun nativeIsLibraryMapped(needle: String): Boolean
    @JvmStatic private external fun nativeAppendLogLine(path: String, line: String): Int
}
