package com.security.scanner.common

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.MDC
import org.springframework.core.annotation.Order
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import java.util.UUID

/**
 * Thread-local holder for request ID across the request lifecycle.
 */
object RequestIdHolder {
    private val holder = ThreadLocal<String>()
    fun set(id: String) = holder.set(id)
    fun get(): String? = holder.get()
    fun clear() = holder.remove()
}

/**
 * Assigns a unique request ID to each request and adds structured logging context.
 */
@Component
@Order(1)
class RequestLoggingFilter : OncePerRequestFilter() {

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        val requestId = request.getHeader("X-Request-ID") ?: UUID.randomUUID().toString()
        val startTime = System.currentTimeMillis()

        RequestIdHolder.set(requestId)
        MDC.put("requestId", requestId)
        MDC.put("method", request.method)
        MDC.put("uri", request.requestURI)

        response.setHeader("X-Request-ID", requestId)

        try {
            filterChain.doFilter(request, response)
        } finally {
            val duration = System.currentTimeMillis() - startTime
            MDC.put("duration", duration.toString())
            MDC.put("status", response.status.toString())
            logger.info("${request.method} ${request.requestURI} - ${response.status} (${duration}ms)")
            MDC.clear()
            RequestIdHolder.clear()
        }
    }
}
