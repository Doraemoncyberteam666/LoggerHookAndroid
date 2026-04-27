package com.dct.hooklogger

import java.util.Locale

/**
 * Helpers for masking the runtime indicators that Frida / Xposed / debugger-detection
 * routines look at. These are pure-Kotlin sanitizers — they take the original probe
 * output and return a "clean" replacement; the smali patch is responsible for swapping
 * the call site so the host code sees the sanitized result.
 */
internal object AntiAnalysisHooks {
    /**
     * Default Frida server / gadget ports. Lines in `/proc/net/tcp[6]` that match any of
     * these (in either local or remote slot) are dropped by [sanitizedProcNetTcp].
     *
     * Only the documented frida-server defaults are listed — adding speculative ports causes
     * false positives that strip benign rows.
     */
    private val FRIDA_PORTS_HEX: Set<String> = setOf(
        // 27042 — frida-server default
        "69A2",
        // 27043 — frida-server "alt" / gadget
        "69A3"
    ).map { it.uppercase(Locale.US) }.toSet()

    private val LIBRARY_BLOCKLIST = listOf(
        "frida-agent",
        "frida-gadget",
        "gum-js-loop",
        "gmain",
        "linjector",
        "xposed",
        "lspatch",
        "lsplant",
        "epic.bridge",
        "substrate",
        "hookzz",
        "whale"
    )

    /**
     * Rewrites every `TracerPid:` line so it reports `0`. Works on `/proc/self/status`,
     * `/proc/<pid>/status`, and any subset thereof.
     */
    fun sanitizedTracerPidStatus(content: String?): String {
        if (content.isNullOrEmpty()) {
            HookRuntime.write("ANTI_ANALYSIS", "sanitizedTracerPidStatus called with null/empty input")
            return content ?: ""
        }
        var replacements = 0
        val out = content.lineSequence().map { line ->
            if (line.startsWith("TracerPid:", ignoreCase = true)) {
                replacements++
                "TracerPid:\t0"
            } else line
        }.joinToString("\n").let {
            // preserve trailing newline if present
            if (content.endsWith("\n") && !it.endsWith("\n")) "$it\n" else it
        }
        HookRuntime.write("ANTI_ANALYSIS", "sanitizedTracerPidStatus rewrote $replacements TracerPid line(s)")
        return out
    }

    /**
     * Drops `/proc/net/tcp[6]` rows whose local-or-remote port matches the Frida block list.
     */
    fun sanitizedProcNetTcp(content: String?): String {
        if (content.isNullOrEmpty()) {
            HookRuntime.write("ANTI_ANALYSIS", "sanitizedProcNetTcp called with null/empty input")
            return content ?: ""
        }
        var dropped = 0
        val out = content.lineSequence().filter { line ->
            val match = TCP_PORT_REGEX.find(line) ?: return@filter true
            val local = match.groupValues[1].uppercase(Locale.US)
            val remote = match.groupValues[2].uppercase(Locale.US)
            val suspicious = FRIDA_PORTS_HEX.contains(local) || FRIDA_PORTS_HEX.contains(remote)
            if (suspicious) dropped++
            !suspicious
        }.joinToString("\n").let {
            if (content.endsWith("\n") && !it.endsWith("\n")) "$it\n" else it
        }
        HookRuntime.write("ANTI_ANALYSIS", "sanitizedProcNetTcp dropped $dropped row(s)")
        return out
    }

    /**
     * Strips lines from `/proc/self/maps` that reference known instrumentation libraries.
     */
    fun sanitizedProcMaps(content: String?): String {
        if (content.isNullOrEmpty()) {
            HookRuntime.write("ANTI_ANALYSIS", "sanitizedProcMaps called with null/empty input")
            return content ?: ""
        }
        var dropped = 0
        val out = content.lineSequence().filter { line ->
            val l = line.lowercase(Locale.US)
            val suspicious = LIBRARY_BLOCKLIST.any { l.contains(it) }
            if (suspicious) dropped++
            !suspicious
        }.joinToString("\n").let {
            if (content.endsWith("\n") && !it.endsWith("\n")) "$it\n" else it
        }
        HookRuntime.write("ANTI_ANALYSIS", "sanitizedProcMaps dropped $dropped line(s)")
        return out
    }

    /**
     * Filters the loaded-library probe (e.g. results of `Runtime.getRuntime().nativeLibraries`).
     */
    fun sanitizedLoadedLibraries(libraries: Array<String>?): Array<String> {
        if (libraries == null) {
            HookRuntime.write("ANTI_ANALYSIS", "sanitizedLoadedLibraries input=null")
            return emptyArray()
        }
        val filtered = libraries.filter { lib ->
            val l = lib.lowercase(Locale.US)
            LIBRARY_BLOCKLIST.none { l.contains(it) }
        }.toTypedArray()
        HookRuntime.write(
            "ANTI_ANALYSIS",
            "sanitizedLoadedLibraries dropped ${libraries.size - filtered.size} of ${libraries.size}"
        )
        return filtered
    }

    fun fakeFridaListening(): Boolean {
        HookRuntime.write("ANTI_ANALYSIS", "fakeFridaListening called, returning false")
        return false
    }

    /**
     * Smali-patch-friendly logger for `System.loadLibrary` / `Runtime.loadLibrary0` calls.
     * Returns the original value so it can be inserted as a "trace tap" before the real call.
     */
    fun loggedLoadLibrary(name: String?): String? {
        HookRuntime.write("NATIVE_LOAD", "System.loadLibrary('${name ?: "null"}')")
        return name
    }

    fun loggedLoad(filename: String?): String? {
        HookRuntime.write("NATIVE_LOAD", "System.load('${filename ?: "null"}')")
        return filename
    }

    /**
     * Matches the local and remote address+port columns in `/proc/net/tcp[6]`. The format is
     * fixed-width, e.g. `0100007F:1F90 00000000:0000`. We only care about the port halves.
     */
    private val TCP_PORT_REGEX = Regex("""\s+[0-9A-Fa-f:]{8,32}:([0-9A-Fa-f]{4})\s+[0-9A-Fa-f:]{8,32}:([0-9A-Fa-f]{4})\s+""")
}
