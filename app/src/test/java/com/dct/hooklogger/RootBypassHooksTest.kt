package com.dct.hooklogger

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RootBypassHooksTest {

    @Test
    fun runtimeCommandReplacesSuOnly() {
        assertEquals("sh", RootBypassHooks.sanitizedRuntimeCommand("su"))
        assertEquals("sh -c id", RootBypassHooks.sanitizedRuntimeCommand("su -c id"))
        assertEquals("sh", RootBypassHooks.sanitizedRuntimeCommand("/system/bin/su"))
        assertEquals("/system/bin/sh -c id", RootBypassHooks.sanitizedRuntimeCommand("/system/bin/sh -c id"))
    }

    @Test
    fun runtimeCommandArgsReplacesSuExecutable() {
        val sanitized = RootBypassHooks.sanitizedRuntimeCommandArgs(arrayOf("su", "-c", "id"))
        assertEquals("sh", sanitized[0])
        assertEquals("-c", sanitized[1])
        assertEquals("id", sanitized[2])
    }

    @Test
    fun systemPropertyOverridesKnownSensitiveKeys() {
        assertEquals("release-keys", RootBypassHooks.sanitizedSystemProperty("ro.build.tags", "test-keys"))
        assertEquals("0", RootBypassHooks.sanitizedSystemProperty("ro.debuggable", "1"))
        assertEquals("preserved", RootBypassHooks.sanitizedSystemProperty("foo.bar", "preserved"))
    }

    @Test
    fun fakeFileExistsForRootInterceptsRootArtifacts() {
        assertFalse(RootBypassHooks.fakeFileExistsForRoot("/system/bin/su"))
        assertFalse(RootBypassHooks.fakeFileExistsForRoot("/data/local/tmp/magisk_files"))
    }

    @Test
    fun procMountsDropsMagiskRows() {
        val input = """
            tmpfs / tmpfs rw 0 0
            magisk /sbin overlay rw 0 0
            ext4 /data ext4 rw 0 0
        """.trimIndent()
        val sanitized = RootBypassHooks.sanitizedProcMounts(input)
        assertFalse(sanitized.contains("magisk"))
        assertTrue(sanitized.contains("/data"))
    }
}
