package com.security.scanner.controller

import com.security.scanner.config.SecurityConfig
import com.security.scanner.domain.dto.AppConfigResponse
import com.security.scanner.domain.dto.ScoringThresholds
import com.security.scanner.domain.dto.ScoringWeights
import com.security.scanner.security.JwtAuthenticationFilter
import com.security.scanner.security.JwtService
import com.security.scanner.security.RateLimitingFilter
import com.security.scanner.service.ConfigService
import org.junit.jupiter.api.Test
import org.mockito.kotlin.whenever
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.context.annotation.Import
import org.springframework.data.redis.core.RedisTemplate
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.context.TestPropertySource
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get

@WebMvcTest(ConfigController::class)
@TestPropertySource(properties = ["app.cors.allowed-origins=http://localhost:3000"])
@Import(SecurityConfig::class)
class ConfigControllerTest {

    @Autowired private lateinit var mockMvc: MockMvc

    @MockBean private lateinit var configService: ConfigService
    @MockBean private lateinit var jwtService: JwtService
    @MockBean private lateinit var jwtAuthenticationFilter: JwtAuthenticationFilter
    @MockBean private lateinit var rateLimitingFilter: RateLimitingFilter
    @MockBean private lateinit var redisTemplate: RedisTemplate<String, String>

    @org.junit.jupiter.api.BeforeEach
    fun setUpFilters() {
        org.mockito.kotlin.doAnswer { invocation ->
            val req = invocation.getArgument<jakarta.servlet.ServletRequest>(0)
            val res = invocation.getArgument<jakarta.servlet.ServletResponse>(1)
            val chain = invocation.getArgument<jakarta.servlet.FilterChain>(2)
            chain.doFilter(req, res)
            null
        }.whenever(jwtAuthenticationFilter).doFilter(org.mockito.kotlin.any(), org.mockito.kotlin.any(), org.mockito.kotlin.any())

        org.mockito.kotlin.doAnswer { invocation ->
            val req = invocation.getArgument<jakarta.servlet.ServletRequest>(0)
            val res = invocation.getArgument<jakarta.servlet.ServletResponse>(1)
            val chain = invocation.getArgument<jakarta.servlet.FilterChain>(2)
            chain.doFilter(req, res)
            null
        }.whenever(rateLimitingFilter).doFilter(org.mockito.kotlin.any(), org.mockito.kotlin.any(), org.mockito.kotlin.any())
    }

    private val mockConfig = AppConfigResponse(
        weights = ScoringWeights(google = 0.5, virusTotal = 0.3, abuseIpDb = 0.2),
        thresholds = ScoringThresholds(safe = 30, suspicious = 60),
        timeoutMs = 10000L,
        maintenance = false,
        maintenanceMessage = null,
        minimumAppVersion = "1.0.0",
        featureFlags = mapOf("parallelScan" to true),
        offlineThreatList = emptyList()
    )

    @Test
    fun `GET config should return 200 without authentication`() {
        whenever(configService.getAppConfig()).thenReturn(mockConfig)

        mockMvc.get("/api/v1/config").andExpect {
            status { isOk() }
            jsonPath("$.success") { value(true) }
            jsonPath("$.data.maintenance") { value(false) }
            jsonPath("$.data.minimumAppVersion") { value("1.0.0") }
            jsonPath("$.data.weights.google") { value(0.5) }
            jsonPath("$.data.thresholds.safe") { value(30) }
        }
    }

    @Test
    fun `GET config should return maintenance true when server is in maintenance mode`() {
        whenever(configService.getAppConfig()).thenReturn(
            mockConfig.copy(maintenance = true, maintenanceMessage = "Scheduled maintenance")
        )

        mockMvc.get("/api/v1/config").andExpect {
            status { isOk() }
            jsonPath("$.data.maintenance") { value(true) }
            jsonPath("$.data.maintenanceMessage") { value("Scheduled maintenance") }
        }
    }

    @Test
    fun `GET config should return 200 even if configService has empty offline threat list`() {
        whenever(configService.getAppConfig()).thenReturn(
            mockConfig.copy(offlineThreatList = emptyList())
        )

        mockMvc.get("/api/v1/config").andExpect {
            status { isOk() }
            jsonPath("$.data.offlineThreatList") { isArray() }
        }
    }
}
