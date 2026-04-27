package com.dct.hooklogger

import java.net.URL

/**
 * Lightweight HTTP request/response loggers. They are not full interceptors — they take values
 * already in scope at a smali patch site and dump them. Pair with smali edits to log
 * `URL.openConnection()`, `OkHttpClient.newCall(request).execute()`, etc.
 */
internal object NetworkHooks {
    fun logHttpRequest(method: String?, url: String?, headers: Map<String, String>?, body: ByteArray?) {
        HookRuntime.safe {
            val sb = StringBuilder()
            sb.append("HTTP > ").append(method ?: "GET").append(' ').append(url ?: "null").append('\n')
            headers?.forEach { (k, v) -> sb.append("  ").append(k).append(": ").append(v).append('\n') }
            if (body != null) sb.append("  body = (").append(body.size).append(" bytes) ").append(asciiPreview(body))
            HookRuntime.write("HTTP", sb.toString().trimEnd())
        }
    }

    fun logHttpResponse(code: Int, headers: Map<String, String>?, body: ByteArray?) {
        HookRuntime.safe {
            val sb = StringBuilder()
            sb.append("HTTP < status=").append(code).append('\n')
            headers?.forEach { (k, v) -> sb.append("  ").append(k).append(": ").append(v).append('\n') }
            if (body != null) sb.append("  body = (").append(body.size).append(" bytes) ").append(asciiPreview(body))
            HookRuntime.write("HTTP", sb.toString().trimEnd())
        }
    }

    fun logUrl(label: String?, url: URL?) {
        HookRuntime.write("HTTP", "${label ?: "url"}: ${url?.toString() ?: "null"}")
    }

    fun logUrl(label: String?, url: String?) {
        HookRuntime.write("HTTP", "${label ?: "url"}: ${url ?: "null"}")
    }

    fun logWebSocket(direction: String?, payload: ByteArray?) {
        HookRuntime.safe {
            val sb = StringBuilder()
            sb.append("WS ").append(direction ?: "?").append(' ')
            if (payload == null) sb.append("null") else sb.append('(').append(payload.size).append(" bytes) ").append(asciiPreview(payload))
            HookRuntime.write("HTTP", sb.toString())
        }
    }

    private fun asciiPreview(bytes: ByteArray, max: Int = 200): String {
        val n = minOf(bytes.size, max)
        val sb = StringBuilder(n)
        for (i in 0 until n) {
            val c = bytes[i].toInt() and 0xFF
            sb.append(if (c in 0x20..0x7E) c.toChar() else '.')
        }
        if (bytes.size > max) sb.append("…")
        return sb.toString()
    }
}
