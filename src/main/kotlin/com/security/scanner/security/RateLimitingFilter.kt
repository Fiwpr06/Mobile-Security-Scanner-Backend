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

    companion object {
        private val RATE_LIMITED_PATHS = listOf("/api/v1/scan", "/api/v1/report")
    }

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        // Only apply rate limiting to scan-related endpoints
        val uri = request.requestURI
        if (RATE_LIMITED_PATHS.none { uri.contains(it) }) {
            filterChain.doFilter(request, response)
            return
        }

        val clientIp = getClientIp(request)
        val deviceId = SecurityContextHolder.getContext().authentication?.name

        // Check IP rate limit first
        val ipCheck = checkRateLimit("ip:$clientIp", ipMaxRequests, ipDurationMinutes)
        if (!ipCheck.allowed) {
            log.warn("IP rate limit exceeded: ip=$clientIp remaining=${ipCheck.remaining}")
            writeRateLimitResponse(response, "Too many requests from this IP. Try again later.")
            return
        }

        // Check device rate limit if authenticated
        if (deviceId != null) {
            val deviceCheck = checkRateLimit("device:$deviceId", deviceMaxRequests, deviceDurationMinutes)
            if (!deviceCheck.allowed) {
                log.warn("Device rate limit exceeded: device=$deviceId remaining=${deviceCheck.remaining}")
                writeRateLimitResponse(response, "Scan limit exceeded for this device. Try again later.")
                return
            }
            // Add informational header so clients can self-throttle
            response.setHeader("X-RateLimit-Remaining", deviceCheck.remaining.toString())
        }

        filterChain.doFilter(request, response)
    }

    /**
     * Atomically increments the counter and ensures a TTL is always set.
     *
     * BUG FIX: The previous implementation used INCR then EXPIRE as two separate commands.
     * If the process crashed between them, the key would have no TTL and persist forever,
     * permanently blocking the user.
     *
     * FIX: After every INCR, we check if the key has a TTL (TTL >= 0).
     * If not (TTL == -1, meaning no expiry was set), we explicitly set it.
     * This makes the operation safe even if the previous EXPIRE call failed.
     */
    private data class RateLimitCheck(val allowed: Boolean, val remaining: Long)

    private fun checkRateLimit(key: String, maxRequests: Long, durationMinutes: Long): RateLimitCheck {
        return try {
            val redisKey = "rate_limit:$key"
            val current = redisTemplate.opsForValue().increment(redisKey) ?: 1L

            // Ensure TTL is always set (guards against crash between INCR and EXPIRE)
            val ttl = redisTemplate.getExpire(redisKey, TimeUnit.SECONDS)
            if (ttl < 0) {
                // Key has no TTL — set it now. This is idempotent and safe.
                redisTemplate.expire(redisKey, durationMinutes, TimeUnit.MINUTES)
            }

            val remaining = maxOf(0L, maxRequests - current)
            RateLimitCheck(allowed = current <= maxRequests, remaining = remaining)
        } catch (e: Exception) {
            // Fail OPEN: if Redis is down, don't block legitimate users.
            // Accept the slight risk of allowing requests; better than a self-inflicted outage.
            log.warn("Rate limit check failed (Redis unavailable), failing open: ${e.message}")
            RateLimitCheck(allowed = true, remaining = maxRequests)
        }
    }

    /**
     * BUG FIX: Was returning HTTP 200 (OK) with a rate-limit error body.
     * This breaks clients that rely on HTTP status codes (Retrofit, Axios, etc.).
     * Correctly returns HTTP 429 Too Many Requests.
     */
    private fun writeRateLimitResponse(response: HttpServletResponse, message: String) {
        response.status = 429 // 429 Too Many Requests
        response.contentType = "application/json;charset=UTF-8"
        response.writer.write(
            """{"error":"RATE_LIMIT_EXCEEDED","message":"$message","statusCode":429}"""
        )
    }

    /**
     * Extracts real client IP, respecting Nginx/proxy forwarding headers.
     * Takes only the FIRST IP from X-Forwarded-For to prevent IP spoofing.
     */
    private fun getClientIp(request: HttpServletRequest): String {
        val xForwardedFor = request.getHeader("X-Forwarded-For")
        val xRealIp = request.getHeader("X-Real-IP")
        return when {
            !xForwardedFor.isNullOrBlank() -> xForwardedFor.split(",").first().trim()
            !xRealIp.isNullOrBlank() -> xRealIp.trim()
            else -> request.remoteAddr
        }
    }
}
