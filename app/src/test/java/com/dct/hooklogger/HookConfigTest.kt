package com.dct.hooklogger

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Properties

class HookConfigTest {

    @After
    fun reset() {
        HookConfig.level = HookConfig.Level.VERBOSE
        HookConfig.jsonOutput = false
        HookConfig.maxLogBytes = 5L * 1024 * 1024
        HookConfig.rotationCount = 3
        HookConfig.queueCapacity = 2048
        HookConfig.clearSuppressedTags()
    }

    @Test
    fun applyPropertiesUpdatesLevelAndJson() {
        val props = Properties().apply {
            setProperty("level", "WARN")
            setProperty("jsonOutput", "true")
            setProperty("maxLogBytes", "1048576")
            setProperty("rotationCount", "5")
            setProperty("tagFilter", "STACK,DUMP")
        }
        HookConfig.applyProperties(props)

        assertEquals(HookConfig.Level.WARN, HookConfig.level)
        assertTrue(HookConfig.jsonOutput)
        assertEquals(1048576L, HookConfig.maxLogBytes)
        assertEquals(5, HookConfig.rotationCount)
        assertTrue(HookConfig.isTagSuppressed("STACK"))
        assertTrue(HookConfig.isTagSuppressed("dump"))
        assertFalse(HookConfig.isTagSuppressed("LOG"))
    }

    @Test
    fun maxLogBytesIsClampedToMinimum() {
        val props = Properties().apply { setProperty("maxLogBytes", "10") }
        HookConfig.applyProperties(props)
        assertEquals(1024L, HookConfig.maxLogBytes)
    }

    @Test
    fun rotationCountIsClampedToReasonableRange() {
        val props = Properties().apply { setProperty("rotationCount", "999") }
        HookConfig.applyProperties(props)
        assertEquals(32, HookConfig.rotationCount)
    }
}
