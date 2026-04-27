package com.dct.hooklogger

import android.content.Intent

/**
 * Helpers for logging Android intents. Useful for tracing app lifecycle / IPC activity
 * after smali patching `startActivity`, `sendBroadcast`, and `startService` call sites.
 */
internal object IntentHooks {
    fun logIntent(label: String?, intent: Intent?) {
        HookRuntime.safe {
            val sb = StringBuilder()
            sb.append(label ?: "intent").append(":\n")
            if (intent == null) {
                sb.append("  intent = null")
                HookRuntime.write("INTENT", sb.toString())
                return@safe
            }
            sb.append("  action    = ").append(intent.action ?: "null").append('\n')
            sb.append("  component = ").append(intent.component?.flattenToShortString() ?: "null").append('\n')
            sb.append("  package   = ").append(intent.`package` ?: "null").append('\n')
            sb.append("  data      = ").append(intent.dataString ?: "null").append('\n')
            sb.append("  type      = ").append(intent.type ?: "null").append('\n')
            sb.append("  flags     = 0x").append(Integer.toHexString(intent.flags)).append('\n')
            val cats = intent.categories
            if (!cats.isNullOrEmpty()) sb.append("  categories= ").append(cats.joinToString(",")).append('\n')
            val extras = intent.extras
            if (extras != null && !extras.isEmpty) {
                sb.append("  extras:\n")
                for (key in extras.keySet()) {
                    @Suppress("DEPRECATION") val v = extras.get(key)
                    sb.append("    ").append(key).append(" = ").append(HookRuntime.safeString(v)).append('\n')
                }
            }
            HookRuntime.write("INTENT", sb.toString().trimEnd())
        }
    }

    fun logActivityStart(intent: Intent?) = logIntent("startActivity", intent)
    fun logService(intent: Intent?) = logIntent("startService", intent)
    fun logBroadcast(intent: Intent?) = logIntent("sendBroadcast", intent)
}
