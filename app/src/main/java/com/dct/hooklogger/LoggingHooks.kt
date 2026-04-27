package com.dct.hooklogger

import android.os.Bundle

internal object LoggingHooks {
    fun log(message: String?) {
        HookRuntime.write("LOG", message ?: "null")
    }

    fun log(tag: String?, message: String?) {
        HookRuntime.write(tag ?: "LOG", message ?: "null")
    }

    fun kv(key: String?, value: Any?) {
        HookRuntime.write("KV", "${key ?: "null"}=${HookRuntime.safeString(value)}")
    }

    fun trace(method: String?) {
        HookRuntime.write("TRACE", method ?: "unknown")
    }

    fun stack(label: String?) {
        val sb = StringBuilder()
        sb.append(label ?: "stack").append('\n')
        Throwable().stackTrace.forEach { sb.append("  at ").append(it).append('\n') }
        HookRuntime.write("STACK", sb.toString())
    }

    fun hex(label: String?, bytes: ByteArray?) {
        if (bytes == null) {
            HookRuntime.write("HEX", "${label ?: "hex"}: null")
            return
        }
        val sb = StringBuilder()
        sb.append(label ?: "hex").append(" (").append(bytes.size).append(" bytes):\n")
        val hexChars = "0123456789ABCDEF".toCharArray()
        for (i in bytes.indices) {
            val v = bytes[i].toInt() and 0xFF
            sb.append(hexChars[v ushr 4]).append(hexChars[v and 0x0F]).append(" ")
            if ((i + 1) % 16 == 0) sb.append("\n")
        }
        HookRuntime.write("HEX", sb.toString())
    }

    fun dumpObj(label: String?, obj: Any?) {
        if (obj == null) {
            HookRuntime.write("DUMP", "${label ?: "obj"}: null")
            return
        }
        val sb = StringBuilder()
        sb.append(label ?: "obj").append(" (").append(obj.javaClass.name).append("):\n")
        try {
            var clazz: Class<*>? = obj.javaClass
            while (clazz != null && clazz != Any::class.java) {
                val fields = clazz.declaredFields
                for (field in fields) {
                    field.isAccessible = true
                    val value = field.get(obj)
                    sb.append("  ").append(field.name).append(" = ").append(HookRuntime.safeString(value)).append("\n")
                }
                clazz = clazz.superclass
            }
        } catch (t: Throwable) {
            sb.append("  <dump failed: ${t.javaClass.name}: ${t.message}>\n")
        }
        HookRuntime.write("DUMP", sb.toString())
    }

    fun bundle(label: String?, bundle: Bundle?) {
        if (bundle == null) {
            HookRuntime.write("BUNDLE", "${label ?: "bundle"}: null")
            return
        }
        val sb = StringBuilder()
        sb.append(label ?: "bundle").append(":\n")
        try {
            for (key in bundle.keySet()) {
                @Suppress("DEPRECATION") val value = bundle.get(key)
                sb.append("  ").append(key).append(" = ").append(HookRuntime.safeString(value)).append("\n")
            }
        } catch (t: Throwable) {
            sb.append("  <bundle parse failed: ${t.javaClass.name}: ${t.message}>\n")
        }
        HookRuntime.write("BUNDLE", sb.toString())
    }

    fun thread() {
        val t = Thread.currentThread()
        HookRuntime.write("THREAD", "id=${t.id}, name=${t.name}")
    }

    fun logPath(): String {
        return HookRuntime.getLogFile()?.absolutePath ?: "uninitialized"
    }

    fun clear() {
        HookRuntime.safe {
            HookRuntime.getLogFile()?.writeText("")
        }
    }
}
