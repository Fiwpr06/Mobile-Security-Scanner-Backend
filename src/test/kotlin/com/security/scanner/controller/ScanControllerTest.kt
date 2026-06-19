package com.security.scanner.controller

import com.fasterxml.jackson.databind.ObjectMapper
import com.security.scanner.config.SecurityConfig
import com.security.scanner.domain.dto.ScanRequest
import com.security.scanner.domain.dto.ScanResponse
import com.security.scanner.domain.dto.ScanSources
import com.security.scanner.domain.dto.SuccessResponse
import com.security.scanner.domain.model.RiskStatus
import com.security.scanner.security.JwtAuthenticationFilter
import com.security.scanner.security.JwtService
import com.security.scanner.security.RateLimitingFilter
import com.security.scanner.service.ScanEngineService
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.eq
import org.mockito.kotlin.whenever
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.context.annotation.Import
import org.springframework.data.redis.core.RedisTemplate
import org.springframework.http.MediaType
import org.springframework.security.test.context.support.WithMockUser
import org.springframework.test.context.TestPropertySource
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.post

@WebMvcTest(ScanController::class)
@TestPropertySource(properties = ["app.cors.allowed-origins=http://localhost:3000"])
@Import(SecurityConfig::class)
class ScanControllerTest {

    @Autowired private lateinit var mockMvc: MockMvc
    @Autowired private lateinit var objectMapper: ObjectMapper

    @MockBean private lateinit var scanEngineService: ScanEngineService
    @MockBean private lateinit var jwtService: JwtService
    @MockBean private lateinit var jwtAuthenticationFilter: JwtAuthenticationFilter
    @MockBean private lateinit var rateLimitingFilter: RateLimitingFilter
    @MockBean private lateinit var redisTemplate: RedisTemplate<String, String>

    @org.junit.jupiter.api.BeforeEach
    fun setUpFilters() {
        org.mockito.kotlin.doAnswer { invocation ->
            val req = invocation.getArgument<jakarta.servlet.http.HttpServletRequest>(0)
            val res = invocation.getArgument<jakarta.servlet.ServletResponse>(1)
            val chain = invocation.getArgument<jakarta.servlet.FilterChain>(2)
            
            if (req.getHeader("Authorization") != null) {
                val context = org.springframework.security.core.context.SecurityContextHolder.createEmptyContext()
                val auth = org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                    "test-device-001", null, listOf(org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_DEVICE"))
                )
                context.authentication = auth
                org.springframework.security.core.context.SecurityContextHolder.setContext(context)
                req.setAttribute("deviceId", "test-device-001")
            }
            
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

    private val mockScanResponse = ScanResponse(
        url = "https://example.com",
        riskScore = 5,
        status = RiskStatus.SAFE,
        sources = ScanSources(),
        scanTimeMs = 100L
    )

    // ─── Success Cases ────────────────────────────────────────────────────────

    @Test
    fun `POST scan should return 200 with scan result for authenticated user`() {
        val request = ScanRequest(url = "https://example.com")

        runBlocking {
            whenever(scanEngineService.scanUrl(org.mockito.kotlin.any(), org.mockito.kotlin.any(), org.mockito.kotlin.anyOrNull())).thenReturn(mockScanResponse)
        }

        val mvcResult = mockMvc.post("/api/v1/scan") {
            contentType = MediaType.APPLICATION_JSON
            header("Authorization", "Bearer valid.token")
            content = objectMapper.writeValueAsString(request)
        }.andReturn()

        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch(mvcResult))
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk)
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.success").value(true))
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.data.url").value("https://example.com"))
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.data.status").value("SAFE"))
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.data.riskScore").value(5))
    }

    @Test
    fun `POST scan should normalize URL without scheme`() {
        val request = ScanRequest(url = "example.com")

        runBlocking {
            whenever(scanEngineService.scanUrl(org.mockito.kotlin.any(), org.mockito.kotlin.any(), org.mockito.kotlin.anyOrNull())).thenReturn(
                mockScanResponse.copy(url = "https://example.com")
            )
        }

        val mvcResult = mockMvc.post("/api/v1/scan") {
            contentType = MediaType.APPLICATION_JSON
            header("Authorization", "Bearer valid.token")
            content = objectMapper.writeValueAsString(request)
        }.andReturn()

        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch(mvcResult))
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk)
            .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.data.url").value("https://example.com"))
    }

    // ─── Auth / Security Failures ─────────────────────────────────────────────

    @Test
    fun `POST scan should return 403 without authentication`() {
        val request = ScanRequest(url = "https://example.com")

        mockMvc.post("/api/v1/scan") {
            contentType = MediaType.APPLICATION_JSON
            content = objectMapper.writeValueAsString(request)
        }.andExpect {
            status { isForbidden() }
        }
    }

    // ─── Validation Failures ──────────────────────────────────────────────────

    @Test
    @WithMockUser(username = "test-device-001", roles = ["DEVICE"])
    fun `POST scan should return 400 for blank URL`() {
        val request = mapOf("url" to "")

        mockMvc.post("/api/v1/scan") {
            contentType = MediaType.APPLICATION_JSON
            content = objectMapper.writeValueAsString(request)
        }.andExpect {
            status { isBadRequest() }
        }
    }

    @Test
    @WithMockUser(username = "test-device-001", roles = ["DEVICE"])
    fun `POST scan should return 400 for missing URL`() {
        val request = mapOf<String, String>()

        mockMvc.post("/api/v1/scan") {
            contentType = MediaType.APPLICATION_JSON
            content = objectMapper.writeValueAsString(request)
        }.andExpect {
            status { isBadRequest() }
        }
    }

    @Test
    @WithMockUser(username = "test-device-001", roles = ["DEVICE"])
    fun `POST scan should return 400 for localhost URL`() {
        val request = ScanRequest(url = "http://localhost/admin")

        mockMvc.post("/api/v1/scan") {
            contentType = MediaType.APPLICATION_JSON
            content = objectMapper.writeValueAsString(request)
        }.andExpect {
            status { isBadRequest() }
        }
    }

    @Test
    @WithMockUser(username = "test-device-001", roles = ["DEVICE"])
    fun `POST scan should return 400 for private IP URL`() {
        val request = ScanRequest(url = "http://192.168.1.1/router")

        mockMvc.post("/api/v1/scan") {
            contentType = MediaType.APPLICATION_JSON
            content = objectMapper.writeValueAsString(request)
        }.andExpect {
            status { isBadRequest() }
        }
    }

    @Test
    @WithMockUser(username = "test-device-001", roles = ["DEVICE"])
    fun `POST scan should return 400 for 10-dot private IP URL`() {
        val request = ScanRequest(url = "http://10.0.0.1/phishing")

        mockMvc.post("/api/v1/scan") {
            contentType = MediaType.APPLICATION_JSON
            content = objectMapper.writeValueAsString(request)
        }.andExpect {
            status { isBadRequest() }
        }
    }

    @Test
    @WithMockUser(username = "test-device-001", roles = ["DEVICE"])
    fun `POST scan should return 400 for missing request body`() {
        mockMvc.post("/api/v1/scan") {
            contentType = MediaType.APPLICATION_JSON
        }.andExpect {
            status { isBadRequest() }
        }
    }
}
