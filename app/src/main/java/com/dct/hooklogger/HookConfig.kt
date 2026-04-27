package com.dct.hooklogger

import android.content.Context
import java.io.File
import java.util.Locale
import java.util.Properties
import java.util.concurrent.ConcurrentHashMap

/**
 * Runtime configuration for the hook logger.
 *
 * Defaults are sensible for reverse-engineering use; when an app's external files dir contains a
 * `dct_hook.properties` file the values below are overridden at [HookRuntime] init time.
 *
 * Recognised keys (all optional):
 *
 * ```
 * level=VERBOSE|DEBUG|INFO|WARN|ERROR
 * tagFilter=TAG1,TAG2          # comma-separated list of tags to drop
 * jsonOutput=true|false        # emit one JSON object per line
 * useLogcat=true|false
 * maxLogBytes=5242880          # rotate when log file exceeds this size (bytes)
 * rotationCount=3              # number of rotated files kept (.1 .. .N)
 * queueCapacity=2048           # bounded executor queue, drops on overflow
 * ```
 */
object HookConfig {
    enum class Level(val value: Int) {
        VERBOSE(0), DEBUG(1), INFO(2), WARN(3), ERROR(4);

        companion object {
            fun parse(s: String?): Level {
                if (s.isNullOrBlank()) return INFO
                return values().firstOrNull { it.name.equals(s.trim(), ignoreCase = true) } ?: INFO
            }
        }
    }

    private const val PROPERTIES_NAME = "dct_hook.properties"

    @Volatile var level: Level = Level.VERBOSE
    @Volatile var jsonOutput: Boolean = false
    @Volatile var useLogcat: Boolean = true
    @Volatile var maxLogBytes: Long = 5L * 1024 * 1024
    @Volatile var rotationCount: Int = 3
    @Volatile var queueCapacity: Int = 2048

    /**
     * Set of suppressed tags. Backed by a [ConcurrentHashMap] so concurrent reads from
     * arbitrary caller threads (`HookRuntime.write` → `isTagSuppressed`) and writes from
     * `Hook.init` / `Hook.suppressTag` cannot corrupt the set or trigger CME.
     */
    private val tagFilter: MutableSet<String> = ConcurrentHashMap.newKeySet()

    fun isTagSuppressed(tag: String): Boolean {
        if (tagFilter.isEmpty()) return false
        return tagFilter.contains(tag.uppercase(Locale.US))
    }

    fun suppressTag(tag: String) {
        tagFilter.add(tag.uppercase(Locale.US))
    }

    fun clearSuppressedTags() {
        tagFilter.clear()
    }

    /**
     * Loads `dct_hook.properties` from the app's external files directory if it exists.
     * Missing keys keep their current default. Errors are swallowed silently.
     */
    fun loadFrom(context: Context?) {
        if (context == null) return
        try {
            val dir = context.getExternalFilesDir(null) ?: context.filesDir ?: return
            val file = File(dir, PROPERTIES_NAME)
            if (!file.exists()) return
            val props = Properties()
            file.inputStream().use { props.load(it) }
            applyProperties(props)
        } catch (_: Throwable) {
            // ignore — config is best-effort
        }
    }

    internal fun applyProperties(props: Properties) {
        props.getProperty("level")?.let { level = Level.parse(it) }
        props.getProperty("jsonOutput")?.let { jsonOutput = it.equals("true", ignoreCase = true) }
        props.getProperty("useLogcat")?.let {
            useLogcat = it.equals("true", ignoreCase = true)
            HookRuntime.useLogcat = useLogcat
        }
        props.getProperty("maxLogBytes")?.toLongOrNull()?.let { maxLogBytes = it.coerceAtLeast(1024L) }
        props.getProperty("rotationCount")?.toIntOrNull()?.let { rotationCount = it.coerceIn(0, 32) }
        props.getProperty("queueCapacity")?.toIntOrNull()?.let { queueCapacity = it.coerceIn(16, 1 shl 16) }
        props.getProperty("tagFilter")?.let { raw ->
            tagFilter.clear()
            raw.split(',').forEach { item ->
                val t = item.trim()
                if (t.isNotEmpty()) tagFilter.add(t.uppercase(Locale.US))
            }
        }
    }
}
