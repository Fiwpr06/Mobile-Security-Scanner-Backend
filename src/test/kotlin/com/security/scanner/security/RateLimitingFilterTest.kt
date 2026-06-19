package com.security.scanner.security

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.kotlin.*
import org.springframework.data.redis.core.RedisTemplate
import org.springframework.data.redis.core.ValueOperations
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import java.util.concurrent.TimeUnit

class RateLimitingFilterTest {

    private lateinit var redisTemplate: RedisTemplate<String, String>
    private lateinit var valueOps: ValueOperations<String, String>
    private lateinit var rateLimitingFilter: RateLimitingFilter
    private lateinit var filterChain: FilterChain

    @BeforeEach
    fun setUp() {
        redisTemplate = mock()
        valueOps = mock()
        filterChain = mock()

        whenever(redisTemplate.opsForValue()).thenReturn(valueOps)
        whenever(redisTemplate.getExpire(any(), any())).thenReturn(-1L) // No TTL set initially
        whenever(redisTemplate.expire(any(), any(), any())).thenReturn(true)

        rateLimitingFilter = RateLimitingFilter(
            redisTemplate = redisTemplate,
            deviceMaxRequests = 5L,
            deviceDurationMinutes = 60L,
            ipMaxRequests = 10L,
            ipDurationMinutes = 60L
        )
    }

    // ─── Bypass Non-Scan Paths ────────────────────────────────────────────────

    @Test
    fun `should bypass rate limiting for non-scan endpoints`() {
        val request = MockHttpServletRequest("POST", "/api/v1/auth/register")
        val response = MockHttpServletResponse()

        rateLimitingFilter.doFilter(request, response, filterChain)

        // Filter chain should proceed, Redis should NOT be called at all
        verify(filterChain).doFilter(request, response)
        verifyNoInteractions(redisTemplate)
        assertThat(response.status).isNotEqualTo(429)
    }

    @Test
    fun `should bypass rate limiting for config endpoint`() {
        val request = MockHttpServletRequest("GET", "/api/v1/config")
        val response = MockHttpServletResponse()

        rateLimitingFilter.doFilter(request, response, filterChain)

        verify(filterChain).doFilter(request, response)
        verifyNoInteractions(redisTemplate)
    }

    // ─── Allow Within Limit ───────────────────────────────────────────────────

    @Test
    fun `should allow scan request when IP count is within limit`() {
        val request = MockHttpServletRequest("POST", "/api/v1/scan")
        request.remoteAddr = "192.0.2.1"
        val response = MockHttpServletResponse()

        // Simulate first request: counter = 1 (within limit of 10)
        whenever(valueOps.increment(any<String>())).thenReturn(1L)

        rateLimitingFilter.doFilter(request, response, filterChain)

        verify(filterChain).doFilter(request, response)
        assertThat(response.status).isNotEqualTo(429)
    }

    // ─── IP Rate Limit Exceeded ───────────────────────────────────────────────

    @Test
    fun `should block with 429 when IP rate limit exceeded`() {
        val request = MockHttpServletRequest("POST", "/api/v1/scan")
        request.remoteAddr = "192.0.2.100"
        val response = MockHttpServletResponse()

        // Simulate counter exceeding IP limit (11 > 10)
        whenever(valueOps.increment(any<String>())).thenReturn(11L)

        rateLimitingFilter.doFilter(request, response, filterChain)

        assertThat(response.status).isEqualTo(429)
        assertThat(response.contentAsString).contains("RATE_LIMIT_EXCEEDED")
        // Filter chain should NOT proceed after rate limit exceeded
        verify(filterChain, never()).doFilter(any(), any())
    }

    @Test
    fun `should respect X-Forwarded-For header for client IP detection`() {
        val request = MockHttpServletRequest("POST", "/api/v1/scan")
        request.addHeader("X-Forwarded-For", "203.0.113.5, 10.0.0.1")
        request.remoteAddr = "10.0.0.1"
        val response = MockHttpServletResponse()

        // Counter within limit
        whenever(valueOps.increment(any<String>())).thenReturn(1L)

        rateLimitingFilter.doFilter(request, response, filterChain)

        // Verify the FIRST IP in X-Forwarded-For (203.0.113.5) is used as key, not the proxy
        verify(valueOps).increment(argThat { contains("203.0.113.5") })
        verify(filterChain).doFilter(request, response)
    }

    @Test
    fun `should prefer X-Real-IP when X-Forwarded-For is absent`() {
        val request = MockHttpServletRequest("POST", "/api/v1/scan")
        request.addHeader("X-Real-IP", "198.51.100.1")
        val response = MockHttpServletResponse()

        whenever(valueOps.increment(any<String>())).thenReturn(1L)

        rateLimitingFilter.doFilter(request, response, filterChain)

        verify(valueOps).increment(argThat { contains("198.51.100.1") })
    }

    // ─── Redis Unavailable — Fail Open ────────────────────────────────────────

    @Test
    fun `should fail open and allow request when Redis is unavailable`() {
        val request = MockHttpServletRequest("POST", "/api/v1/scan")
        request.remoteAddr = "192.0.2.1"
        val response = MockHttpServletResponse()

        // Redis throws an exception (simulating connection failure)
        whenever(valueOps.increment(any<String>())).thenThrow(RuntimeException("Redis connection refused"))

        rateLimitingFilter.doFilter(request, response, filterChain)

        // Must fail OPEN: request should be allowed, not blocked
        verify(filterChain).doFilter(request, response)
        assertThat(response.status).isNotEqualTo(429)
    }

    // ─── TTL Safety (No Eternal Keys) ────────────────────────────────────────

    @Test
    fun `should set TTL when Redis key has no expiry (guards against crash between INCR and EXPIRE)`() {
        val request = MockHttpServletRequest("POST", "/api/v1/scan")
        request.remoteAddr = "192.0.2.1"
        val response = MockHttpServletResponse()

        whenever(valueOps.increment(any<String>())).thenReturn(1L)
        // Simulate key with no TTL (TTL = -1)
        whenever(redisTemplate.getExpire(any(), any())).thenReturn(-1L)

        rateLimitingFilter.doFilter(request, response, filterChain)

        // Must set TTL to prevent infinite rate limit persistence
        verify(redisTemplate, atLeastOnce()).expire(any(), any(), any())
    }

    @Test
    fun `should NOT reset TTL if key already has a valid expiry`() {
        val request = MockHttpServletRequest("POST", "/api/v1/scan")
        request.remoteAddr = "192.0.2.1"
        val response = MockHttpServletResponse()

        whenever(valueOps.increment(any<String>())).thenReturn(3L)
        // Simulate key WITH TTL (1800 seconds remaining)
        whenever(redisTemplate.getExpire(any(), any())).thenReturn(1800L)

        rateLimitingFilter.doFilter(request, response, filterChain)

        // Should NOT reset TTL if it's already set
        verify(redisTemplate, never()).expire(any(), any(), any())
    }
}
