package com.dct.hooklogger

import java.security.Key
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.Mac

/**
 * Logging helpers for cryptographic primitives. The intent is to give a reverse engineer a
 * full picture of every `Cipher.doFinal`, `MessageDigest.digest`, and `Mac.doFinal` call in
 * a target app — including the algorithm, mode, IV, key bytes (algorithm + first N hex), and
 * payload preview.
 *
 * Smali patterns:
 *
 * ```smali
 * # Tap a Cipher.doFinal(byte[]) call by inserting a log call right before it:
 * invoke-static {v0, v1, v2}, Lcom/dct/hooklogger/Hook;->logCipher(Ljava/lang/String;Ljavax/crypto/Cipher;[B)V
 *
 * # Same for the Mac case:
 * invoke-static {v0, v1, v2}, Lcom/dct/hooklogger/Hook;->logMac(Ljava/lang/String;Ljavax/crypto/Mac;[B)V
 * ```
 */
internal object CryptoHooks {
    fun logCipher(label: String?, cipher: Cipher?, input: ByteArray?, output: ByteArray? = null) {
        HookRuntime.safe {
            val sb = StringBuilder()
            sb.append(label ?: "cipher").append(":\n")
            if (cipher != null) {
                sb.append("  algorithm = ").append(cipher.algorithm).append('\n')
                runCatching { sb.append("  block_size = ").append(cipher.blockSize).append('\n') }
                runCatching { cipher.iv?.let { sb.append("  iv = ").append(hexPreview(it, 32)).append('\n') } }
                runCatching {
                    val provider = cipher.provider?.name
                    if (provider != null) sb.append("  provider = ").append(provider).append('\n')
                }
            } else {
                sb.append("  cipher = null\n")
            }
            if (input != null) sb.append("  input  = ").append(byteArrayPreview(input)).append('\n')
            if (output != null) sb.append("  output = ").append(byteArrayPreview(output)).append('\n')
            HookRuntime.write("CRYPTO", sb.toString().trimEnd())
        }
    }

    fun logMessageDigest(label: String?, digest: MessageDigest?, input: ByteArray?, output: ByteArray? = null) {
        HookRuntime.safe {
            val sb = StringBuilder()
            sb.append(label ?: "digest").append(":\n")
            if (digest != null) {
                sb.append("  algorithm = ").append(digest.algorithm).append('\n')
            }
            if (input != null) sb.append("  input  = ").append(byteArrayPreview(input)).append('\n')
            if (output != null) sb.append("  digest = ").append(hexPreview(output, 64)).append('\n')
            HookRuntime.write("CRYPTO", sb.toString().trimEnd())
        }
    }

    fun logMac(label: String?, mac: Mac?, input: ByteArray?, output: ByteArray? = null) {
        HookRuntime.safe {
            val sb = StringBuilder()
            sb.append(label ?: "mac").append(":\n")
            if (mac != null) sb.append("  algorithm = ").append(mac.algorithm).append('\n')
            if (input != null) sb.append("  input  = ").append(byteArrayPreview(input)).append('\n')
            if (output != null) sb.append("  mac = ").append(hexPreview(output, 64)).append('\n')
            HookRuntime.write("CRYPTO", sb.toString().trimEnd())
        }
    }

    fun logKey(label: String?, key: Key?) {
        HookRuntime.safe {
            val sb = StringBuilder()
            sb.append(label ?: "key").append(":\n")
            if (key == null) {
                sb.append("  key = null")
                HookRuntime.write("CRYPTO", sb.toString())
                return@safe
            }
            sb.append("  algorithm = ").append(key.algorithm).append('\n')
            sb.append("  format    = ").append(key.format ?: "<opaque>").append('\n')
            runCatching {
                val bytes = key.encoded
                if (bytes != null) sb.append("  bytes     = ").append(hexPreview(bytes, 32)).append('\n')
            }
            HookRuntime.write("CRYPTO", sb.toString().trimEnd())
        }
    }

    private fun byteArrayPreview(bytes: ByteArray, max: Int = 64): String {
        val sb = StringBuilder()
        sb.append('(').append(bytes.size).append(" bytes) ")
        sb.append(hexPreview(bytes, max))
        if (bytes.size > max) sb.append("…")
        return sb.toString()
    }

    private fun hexPreview(bytes: ByteArray, max: Int): String {
        val n = minOf(bytes.size, max)
        val sb = StringBuilder(n * 2)
        for (i in 0 until n) {
            val v = bytes[i].toInt() and 0xFF
            sb.append(HEX[v ushr 4]).append(HEX[v and 0x0F])
        }
        return sb.toString()
    }

    private val HEX = "0123456789abcdef".toCharArray()
}
