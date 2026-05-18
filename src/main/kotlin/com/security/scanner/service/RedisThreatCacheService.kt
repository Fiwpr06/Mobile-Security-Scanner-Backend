package com.security.scanner.service

import com.fasterxml.jackson.databind.ObjectMapper
import org.slf4j.LoggerFactory
import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.stereotype.Service
import java.util.concurrent.TimeUnit

@Service
class RedisThreatCacheService(
    private val redisTemplate: StringRedisTemplate,
    private val objectMapper: ObjectMapper
) {
    private val log = LoggerFactory.getLogger(javaClass)

    private val URL_PREFIX = "mal:url:"
    private val DOMAIN_PREFIX = "mal:dom:"
    
    // Advanced TTL Strategy (Negative Caching)
    private val DANGEROUS_TTL_DAYS = 30L
    private val SAFE_TTL_MINUTES = 15L
    private val UNKNOWN_TTL_MINUTES = 3L
    private val DOMAIN_TTL_DAYS = 90L

    fun cacheScanResult(urlHash: String, verdict: String, confidence: Double, threatType: String?) {
        val cachedThreat = CachedThreat(
            verdict = verdict,
            confidence = confidence,
            threatType = threatType ?: "NONE"
        )
        
        val ttlSeconds = when (verdict.uppercase()) {
            "SAFE" -> {
                if (confidence < 0.5) TimeUnit.MINUTES.toSeconds(3)
                else TimeUnit.MINUTES.toSeconds(15)
            }
            "SUSPICIOUS" -> TimeUnit.MINUTES.toSeconds(30)
            "DANGEROUS" -> {
                if (confidence > 0.8) TimeUnit.DAYS.toSeconds(30)
                else TimeUnit.DAYS.toSeconds(7)
            }
            "UNKNOWN" -> TimeUnit.MINUTES.toSeconds(1)
            else -> TimeUnit.MINUTES.toSeconds(1)
        }

        try {
            val jsonValue = objectMapper.writeValueAsString(cachedThreat)
            redisTemplate.opsForValue().set("$URL_PREFIX$urlHash", jsonValue, ttlSeconds, TimeUnit.SECONDS)
        } catch (e: Exception) {
            log.error("Failed to serialize and cache threat for hash=$urlHash", e)
        }
    }

    // Kept for backward compatibility with older bulk ingestions if needed
    fun cacheDangerousUrl(urlHash: String, confidence: Double, threatType: String) {
        cacheScanResult(urlHash, "DANGEROUS", confidence, threatType)
    }

    fun cacheDangerousDomain(domain: String) {
        redisTemplate.opsForValue().set("$DOMAIN_PREFIX$domain", "blocked", DOMAIN_TTL_DAYS, TimeUnit.DAYS)
    }

    fun getCachedUrlThreat(urlHash: String): CachedThreat? {
        val value = redisTemplate.opsForValue().get("$URL_PREFIX$urlHash") ?: return null
        
        return try {
            // Attempt to parse as JSON first (New format)
            if (value.startsWith("{")) {
                objectMapper.readValue(value, CachedThreat::class.java)
            } else {
                // Fallback for old string format: "confidence:threatType"
                val parts = value.split(":")
                if (parts.size >= 2) {
                    CachedThreat(
                        verdict = "DANGEROUS", // Old cache only stored dangerous URLs
                        confidence = parts[0].toDoubleOrNull() ?: 1.0,
                        threatType = parts[1]
                    )
                } else {
                    CachedThreat("DANGEROUS", 1.0, "MALWARE")
                }
            }
        } catch (e: Exception) {
            log.warn("Failed to parse cached threat for hash=$urlHash, invalidating cache", e)
            redisTemplate.delete("$URL_PREFIX$urlHash")
            null
        }
    }

    fun isDomainBlocked(domain: String): Boolean {
        return redisTemplate.hasKey("$DOMAIN_PREFIX$domain") == true
    }
}

data class CachedThreat(
    val verdict: String,
    val confidence: Double,
    val threatType: String
)
