package com.security.scanner.controller

import com.fasterxml.jackson.databind.ObjectMapper
import com.security.scanner.domain.dto.DeviceRegistrationRequest
import com.security.scanner.domain.dto.AuthResponse
import com.security.scanner.domain.dto.SuccessResponse
import com.security.scanner.service.AuthService
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.whenever
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.context.annotation.Import
import org.springframework.http.MediaType
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.post
import com.security.scanner.config.SecurityConfig
import com.security.scanner.security.JwtAuthenticationFilter
import com.security.scanner.security.JwtService
import com.security.scanner.security.RateLimitingFilter
import org.springframework.data.redis.core.RedisTemplate

@WebMvcTest(AuthController::class)
class AuthControllerTest {

    @Autowired private lateinit var mockMvc: MockMvc
    @Autowired private lateinit var objectMapper: ObjectMapper

    @MockBean private lateinit var authService: AuthService
    @MockBean private lateinit var jwtService: JwtService
    @MockBean private lateinit var jwtAuthenticationFilter: JwtAuthenticationFilter
    @MockBean private lateinit var rateLimitingFilter: RateLimitingFilter
    @MockBean private lateinit var redisTemplate: RedisTemplate<String, String>

    @Test
    fun `POST auth register should return JWT token`() {
        val request = DeviceRegistrationRequest(deviceId = "test-device-12345678", platform = "android")
        val mockResponse = AuthResponse(
            accessToken = "mock.jwt.token",
            expiresIn = 86400000L,
            deviceId = "test-device-12345678"
        )

        whenever(authService.registerDevice(any())).thenReturn(mockResponse)

        mockMvc.post("/api/v1/auth/register") {
            contentType = MediaType.APPLICATION_JSON
            content = objectMapper.writeValueAsString(request)
        }.andExpect {
            status { isOk() }
            jsonPath("$.success") { value(true) }
            jsonPath("$.data.accessToken") { value("mock.jwt.token") }
            jsonPath("$.data.deviceId") { value("test-device-12345678") }
        }
    }

    @Test
    fun `POST auth register should return 400 for blank device ID`() {
        val request = mapOf("deviceId" to "")

        mockMvc.post("/api/v1/auth/register") {
            contentType = MediaType.APPLICATION_JSON
            content = objectMapper.writeValueAsString(request)
        }.andExpect {
            status { isBadRequest() }
            jsonPath("$.error") { value("VALIDATION_ERROR") }
        }
    }

    @Test
    fun `POST auth register should return 400 for missing device ID`() {
        val request = mapOf("platform" to "android")

        mockMvc.post("/api/v1/auth/register") {
            contentType = MediaType.APPLICATION_JSON
            content = objectMapper.writeValueAsString(request)
        }.andExpect {
            status { isBadRequest() }
        }
    }
}
