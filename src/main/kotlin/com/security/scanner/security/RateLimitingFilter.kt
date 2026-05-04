package com.security.scanner.security

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.data.redis.core.RedisTemplate
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import java.time.Duration
import java.util.concurrent.TimeUnit

@Component
class RateLimitingFilter(
    private val redisTemplate: RedisTemplate<String, String>,
    @Value("\${app.rate-limit.per-device.requests:100}") private val deviceMaxRequests: Long,
    @Value("\${app.rate-limit.per-device.duration-minutes:60}") private val deviceDurationMinutes: Long,
    @Value("\${app.rate-limit.per-ip.requests:200}") private val ipMaxRequests: Long,
    @Value("\${app.rate-limit.per-ip.duration-minutes:60}") private val ipDurationMinutes: Long
) : OncePerRequestFilter() {

    private val log = LoggerFactory.getLogger(javaClass)

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        // Only apply rate limiting to scan endpoints
        if (!request.requestURI.contains("/api/v1/scan") &&
            !request.requestURI.contains("/api/v1/report")) {
            filterChain.doFilter(request, response)
            return
        }

        val clientIp = getClientIp(request)
        val deviceId = SecurityContextHolder.getContext().authentication?.name

        // Check IP rate limit
        if (!checkRateLimit("ip:$clientIp", ipMaxRequests, ipDurationMinutes)) {
            log.warn("IP rate limit exceeded for IP: $clientIp")
            response.status = HttpServletResponse.SC_OK
            response.contentType = "application/json"
            response.writer.write(
                """{"error":"RATE_LIMIT_EXCEEDED","message":"Too many requests from this IP. Try again later.","statusCode":429}"""
            )
            return
        }

        // Check device rate limit
        if (deviceId != null && !checkRateLimit("device:$deviceId", deviceMaxRequests, deviceDurationMinutes)) {
            log.warn("Device rate limit exceeded for device: $deviceId")
            response.status = HttpServletResponse.SC_OK
            response.contentType = "application/json"
            response.writer.write(
                """{"error":"RATE_LIMIT_EXCEEDED","message":"Scan limit exceeded for this device. Try again later.","statusCode":429}"""
            )
            return
        }

        filterChain.doFilter(request, response)
    }

    private fun checkRateLimit(key: String, maxRequests: Long, durationMinutes: Long): Boolean {
        return try {
            val redisKey = "rate_limit:$key"
            val ops = redisTemplate.opsForValue()
            val current = ops.increment(redisKey) ?: 1L

            if (current == 1L) {
                redisTemplate.expire(redisKey, durationMinutes, TimeUnit.MINUTES)
            }

            current <= maxRequests
        } catch (e: Exception) {
            log.warn("Rate limit check failed (Redis unavailable), allowing request: ${e.message}")
            true // Fail open if Redis is down
        }
    }

    private fun getClientIp(request: HttpServletRequest): String {
        val xForwardedFor = request.getHeader("X-Forwarded-For")
        val xRealIp = request.getHeader("X-Real-IP")
        return when {
            !xForwardedFor.isNullOrBlank() -> xForwardedFor.split(",").first().trim()
            !xRealIp.isNullOrBlank() -> xRealIp
            else -> request.remoteAddr
        }
    }
}
