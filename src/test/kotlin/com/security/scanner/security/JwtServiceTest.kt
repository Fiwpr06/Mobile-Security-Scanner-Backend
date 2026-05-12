package com.security.scanner.security

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class JwtServiceTest {

    private lateinit var jwtService: JwtService
    private val secret = "test-secret-key-for-unit-testing-must-be-at-least-32-chars-long!"
    private val expiration = 3600000L // 1 hour

    @BeforeEach
    fun setUp() {
        jwtService = JwtService(secret, expiration)
    }

    @Test
    fun `should generate valid token for device`() {
        val deviceId = "test-device-001"
        val token = jwtService.generateToken(deviceId)
        assertThat(token).isNotBlank()
    }

    @Test
    fun `should extract device ID from valid token`() {
        val deviceId = "test-device-001"
        val token = jwtService.generateToken(deviceId)
        val extracted = jwtService.extractDeviceId(token)
        assertThat(extracted).isEqualTo(deviceId)
    }

    @Test
    fun `should validate a fresh token as valid`() {
        val token = jwtService.generateToken("device-abc")
        assertThat(jwtService.isTokenValid(token)).isTrue()
    }

    @Test
    fun `should reject invalid token`() {
        assertThat(jwtService.isTokenValid("not.a.valid.token")).isFalse()
    }

    @Test
    fun `should reject tampered token`() {
        val token = jwtService.generateToken("device-001")
        val tampered = token.dropLast(5) + "XXXXX"
        assertThat(jwtService.isTokenValid(tampered)).isFalse()
    }

    @Test
    fun `should return expiration value`() {
        assertThat(jwtService.getExpiration()).isEqualTo(expiration)
    }
}
