package com.security.scanner.security

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Service
import java.util.Date
import javax.crypto.SecretKey

@Service
class JwtService(
    @Value("\${app.jwt.secret}") private val secret: String,
    @Value("\${app.jwt.access-token-expiration}") private val accessTokenExpiration: Long
) {
    private val log = LoggerFactory.getLogger(javaClass)

    private val signingKey: SecretKey by lazy {
        val keyBytes = secret.toByteArray()
        require(keyBytes.size >= 32) { "JWT secret must be at least 256 bits (32 bytes)" }
        Keys.hmacShaKeyFor(keyBytes)
    }

    fun generateToken(deviceId: String, userId: String? = null): String {
        val builder = Jwts.builder()
            .subject(deviceId)
            .claim("type", "access")

        if (userId != null) {
            builder.claim("userId", userId)
        }

        return builder
            .issuedAt(Date())
            .expiration(Date(System.currentTimeMillis() + accessTokenExpiration))
            .signWith(signingKey)
            .compact()
    }

    fun extractDeviceId(token: String): String? {
        return try {
            val claims = parseClaims(token)
            claims.subject
        } catch (e: Exception) {
            log.warn("Failed to extract device ID from token: ${e.message}")
            null
        }
    }

    fun extractUserId(token: String): String? {
        return try {
            val claims = parseClaims(token)
            claims.get("userId", String::class.java)
        } catch (e: Exception) {
            null
        }
    }

    fun isTokenValid(token: String): Boolean {
        return try {
            val claims = parseClaims(token)
            claims.expiration.after(Date())
        } catch (e: Exception) {
            false
        }
    }

    fun getExpiration(): Long = accessTokenExpiration

    private fun parseClaims(token: String): Claims {
        return Jwts.parser()
            .verifyWith(signingKey)
            .build()
            .parseSignedClaims(token)
            .payload
    }
}
