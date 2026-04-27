package com.dct.hooklogger

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AntiAnalysisHooksTest {

    @Test
    fun tracerPidIsRewrittenToZero() {
        val input = """
            Name:	app_process
            State:	S (sleeping)
            Tgid:	1234
            Pid:	1234
            PPid:	1
            TracerPid:	5678
            Uid:	0	0	0	0
        """.trimIndent() + "\n"

        val out = AntiAnalysisHooks.sanitizedTracerPidStatus(input)
        assertTrue("expected rewritten line", out.lineSequence().any { it == "TracerPid:\t0" })
        assertFalse("original tracer pid still present", out.contains("TracerPid:\t5678"))
        // trailing newline preserved
        assertTrue(out.endsWith("\n"))
    }

    @Test
    fun tracerPidNoOpsWhenAbsent() {
        val input = "Name:	app_process\nPid:	42\n"
        val out = AntiAnalysisHooks.sanitizedTracerPidStatus(input)
        assertEquals(input, out)
    }

    @Test
    fun procNetTcpDropsFridaPortRows() {
        // Row 1 has localPort=69A2 (27042); Row 2 is benign.
        val frida = "  0: 0100007F:69A2 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0"
        val benign = "  1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 67890 1 0000000000000000 100 0 0 10 0"
        val header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
        val input = "$header\n$frida\n$benign\n"

        val out = AntiAnalysisHooks.sanitizedProcNetTcp(input)
        assertFalse("frida row should be dropped", out.contains("69A2"))
        assertTrue("benign row should remain", out.contains("1F90"))
        assertTrue("header should remain", out.contains("local_address"))
    }

    @Test
    fun procMapsDropsBlocklistedLibraries() {
        val input = """
            12345000-12350000 r-xp 00000000 fd:00 1234   /data/local/tmp/frida-agent-64.so
            22345000-22350000 r-xp 00000000 fd:00 5678   /system/lib64/libc.so
            32345000-32350000 r-xp 00000000 fd:00 9999   /apex/com.android.runtime/lib64/libxposed.so
        """.trimIndent() + "\n"

        val out = AntiAnalysisHooks.sanitizedProcMaps(input)
        assertFalse(out.contains("frida-agent-64.so"))
        assertFalse(out.contains("libxposed.so"))
        assertTrue(out.contains("libc.so"))
    }

    @Test
    fun loadedLibrariesFilterDropsKnownInstrumentation() {
        val libs = arrayOf("libc.so", "libfrida-gadget.so", "libssl.so", "libsubstrate.so")
        val out = AntiAnalysisHooks.sanitizedLoadedLibraries(libs)
        assertEquals(2, out.size)
        assertTrue(out.contains("libc.so"))
        assertTrue(out.contains("libssl.so"))
    }

    @Test
    fun nullInputsReturnEmptyStringForRebuilders() {
        assertEquals("", AntiAnalysisHooks.sanitizedTracerPidStatus(null))
        assertEquals("", AntiAnalysisHooks.sanitizedProcNetTcp(null))
        assertEquals("", AntiAnalysisHooks.sanitizedProcMaps(null))
    }
}
