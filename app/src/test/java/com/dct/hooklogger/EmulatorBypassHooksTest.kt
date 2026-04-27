package com.dct.hooklogger

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class EmulatorBypassHooksTest {

    @Test
    fun hardwareReplacedForKnownEmulatorSignatures() {
        assertEquals("qcom", EmulatorBypassHooks.sanitizedHardware("goldfish"))
        assertEquals("qcom", EmulatorBypassHooks.sanitizedHardware("ranchu"))
        assertEquals("qcom", EmulatorBypassHooks.sanitizedHardware("qemu_arm64"))
        assertEquals("qcom-real", EmulatorBypassHooks.sanitizedHardware("qcom-real"))
    }

    @Test
    fun kernelQemuFlippedFromOneToZero() {
        assertEquals("0", EmulatorBypassHooks.sanitizedKernelQemu("1"))
        assertEquals("0", EmulatorBypassHooks.sanitizedKernelQemu("0"))
        assertEquals("0", EmulatorBypassHooks.sanitizedKernelQemu(null))
    }

    @Test
    fun fingerprintReplacedWhenSuspicious() {
        val out = EmulatorBypassHooks.sanitizedFingerprint("generic/sdk_gphone_x86")
        assertNotEquals("generic/sdk_gphone_x86", out)
        assertTrue(out.contains("release-keys"))
    }

    @Test
    fun imeiPlacesholderForEmptyOrZero() {
        assertEquals("356938035643809", EmulatorBypassHooks.sanitizedImei(""))
        assertEquals("356938035643809", EmulatorBypassHooks.sanitizedImei("000000000000000"))
        assertEquals("123456789012345", EmulatorBypassHooks.sanitizedImei("123456789012345"))
    }

    @Test
    fun sensorCountIsBumpedWhenLow() {
        assertEquals(12, EmulatorBypassHooks.sanitizedSensorCount(0))
        assertEquals(12, EmulatorBypassHooks.sanitizedSensorCount(7))
        assertEquals(20, EmulatorBypassHooks.sanitizedSensorCount(20))
    }

    @Test
    fun batteryLevelIsBoundedAndBumpedWhenLow() {
        assertEquals(77, EmulatorBypassHooks.sanitizedBatteryLevel(0))
        assertEquals(77, EmulatorBypassHooks.sanitizedBatteryLevel(-50))
        assertEquals(50, EmulatorBypassHooks.sanitizedBatteryLevel(50))
        assertEquals(100, EmulatorBypassHooks.sanitizedBatteryLevel(150))
    }
}
