package com.security.scanner.security

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.LoggerFactory
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter

@Component
class JwtAuthenticationFilter(
    private val jwtService: JwtService
) : OncePerRequestFilter() {

    private val log = LoggerFactory.getLogger(javaClass)

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        val authHeader = request.getHeader("Authorization")

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response)
            return
        }

        val token = authHeader.removePrefix("Bearer ").trim()

        try {
            if (jwtService.isTokenValid(token)) {
                val deviceId = jwtService.extractDeviceId(token)
                if (deviceId != null) {
                    val auth = UsernamePasswordAuthenticationToken(
                        deviceId,
                        null,
                        listOf(SimpleGrantedAuthority("ROLE_DEVICE"))
                    )
                    auth.details = request.remoteAddr
                    SecurityContextHolder.getContext().authentication = auth
                    // Pass device_id to request for logging
                    request.setAttribute("deviceId", deviceId)
                }
            }
        } catch (e: Exception) {
            log.warn("JWT authentication failed: ${e.message}")
            SecurityContextHolder.clearContext()
        }

        filterChain.doFilter(request, response)
    }
}
