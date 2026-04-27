package com.dct.hooklogger

import android.content.Context
import android.os.Environment
import android.util.Log
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadFactory
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

internal object HookRuntime {
    internal const val TAG = "DCT-HOOK"
    private const val LOG_FILE_NAME = "dct_hook.log"

    @Volatile
    var appContext: Context? = null

    @Volatile
    var useLogcat = true

    private val io = ThreadPoolExecutor(
        1, 1,
        0L, TimeUnit.MILLISECONDS,
        LinkedBlockingQueue<Runnable>(HookConfig.queueCapacity),
        ThreadFactory { r ->
            Thread(r, "dct-hook-io").apply { isDaemon = true }
        },
        ThreadPoolExecutor.DiscardPolicy() // drop on bounded-queue overflow
    )

    private val timeFormatter = ThreadLocal.withInitial {
        SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US)
    }

    fun write(tag: String, message: String) {
        write(HookConfig.Level.INFO, tag, message)
    }

    fun write(level: HookConfig.Level, tag: String, message: String) {
        if (level.value < HookConfig.level.value) return
        if (HookConfig.isTagSuppressed(tag)) return

        safe {
            val ts = (timeFormatter.get() ?: SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US)).format(Date())
            val line = if (HookConfig.jsonOutput) buildJson(ts, level, tag, message) else "$ts [${level.name}/$tag] $message"
            if (HookConfig.useLogcat && useLogcat) {
                when (level) {
                    HookConfig.Level.VERBOSE -> Log.v(TAG, "[$tag] $message")
                    HookConfig.Level.DEBUG -> Log.d(TAG, "[$tag] $message")
                    HookConfig.Level.INFO -> Log.i(TAG, "[$tag] $message")
                    HookConfig.Level.WARN -> Log.w(TAG, "[$tag] $message")
                    HookConfig.Level.ERROR -> Log.e(TAG, "[$tag] $message")
                }
            }
            io.execute {
                safe {
                    val file = getLogFile() ?: return@safe
                    file.parentFile?.mkdirs()
                    rotateIfNeeded(file)
                    file.appendText(line + "\n")
                }
            }
        }
    }

    /**
     * Drains pending I/O so callers (e.g. instrumentation) can rely on log
     * lines being flushed before the process is killed.
     */
    fun flush(timeoutMs: Long = 1500L) {
        val latch = java.util.concurrent.CountDownLatch(1)
        try {
            io.execute { latch.countDown() }
        } catch (_: Throwable) {
            return
        }
        try {
            latch.await(timeoutMs, TimeUnit.MILLISECONDS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }

    fun getLogFile(): File? {
        val ctx = appContext

        if (ctx != null) {
            val dir = ctx.getExternalFilesDir(null) ?: ctx.filesDir
            return File(dir, LOG_FILE_NAME)
        }

        @Suppress("DEPRECATION")
        val docs = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS) ?: return null
        return File(File(docs, "DCTHookLogger"), LOG_FILE_NAME)
    }

    fun safeString(value: Any?): String {
        if (value == null) return "null"
        return try {
            when (value) {
                is ByteArray -> value.contentToString()
                is ShortArray -> value.contentToString()
                is IntArray -> value.contentToString()
                is LongArray -> value.contentToString()
                is FloatArray -> value.contentToString()
                is DoubleArray -> value.contentToString()
                is BooleanArray -> value.contentToString()
                is CharArray -> value.contentToString()
                is Array<*> -> value.contentDeepToString()
                else -> value.toString()
            }
        } catch (t: Throwable) {
            "<toString failed: ${t.javaClass.name}: ${t.message}>"
        }
    }

    /**
     * Run [block], log success/failure under `REFLECT`, and return its result (or null on
     * failure). Used by [ReflectionHooks] to keep smali patches crash-safe.
     */
    inline fun <T> runCatchingForJni(label: String, crossinline block: () -> T): T? {
        return try {
            val r = block()
            write("REFLECT", "$label -> ok")
            r
        } catch (t: Throwable) {
            // Reflection invokes wrap thrown exceptions; surface the underlying cause.
            val real = (t as? java.lang.reflect.InvocationTargetException)?.targetException ?: t
            write(HookConfig.Level.WARN, "REFLECT", "$label failed: ${real.javaClass.name}: ${real.message}")
            null
        }
    }

    inline fun safe(block: () -> Unit) {
        try {
            block()
        } catch (ignored: Throwable) {
            if (useLogcat && HookConfig.useLogcat) {
                Log.e(TAG, "suppressed: ${ignored.javaClass.name}: ${ignored.message}")
            }
        }
    }

    private fun rotateIfNeeded(file: File) {
        val limit = HookConfig.maxLogBytes
        if (limit <= 0) return
        if (!file.exists() || file.length() < limit) return

        val keep = HookConfig.rotationCount
        if (keep <= 0) {
            file.delete()
            return
        }

        // dct_hook.log.(N) -> drop, then shift dct_hook.log.(i) -> dct_hook.log.(i+1).
        val parent = file.parentFile ?: return
        val name = file.name
        File(parent, "$name.$keep").delete()
        for (i in (keep - 1) downTo 1) {
            val src = File(parent, "$name.$i")
            if (src.exists()) src.renameTo(File(parent, "$name.${i + 1}"))
        }
        file.renameTo(File(parent, "$name.1"))
    }

    /**
     * JSON-line serialiser. Hand-rolled to avoid pulling in org.json on the bytecode hook path
     * and to keep the format stable across Android versions.
     */
    private fun buildJson(ts: String, level: HookConfig.Level, tag: String, message: String): String {
        val sb = StringBuilder(message.length + 64)
        sb.append('{')
        sb.append("\"ts\":\"").append(ts).append("\",")
        sb.append("\"level\":\"").append(level.name).append("\",")
        sb.append("\"tag\":\"").append(escapeJson(tag)).append("\",")
        sb.append("\"msg\":\"").append(escapeJson(message)).append("\"")
        sb.append('}')
        return sb.toString()
    }

    private fun escapeJson(s: String): String {
        val sb = StringBuilder(s.length + 8)
        for (i in s.indices) {
            when (val c = s[i]) {
                '\\' -> sb.append("\\\\")
                '"' -> sb.append("\\\"")
                '\b' -> sb.append("\\b")
                '\u000C' -> sb.append("\\f")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else -> if (c.code < 0x20) sb.append(String.format(Locale.US, "\\u%04x", c.code)) else sb.append(c)
            }
        }
        return sb.toString()
    }
}
