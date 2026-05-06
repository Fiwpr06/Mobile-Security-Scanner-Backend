package com.security.scanner.service

import com.security.scanner.domain.model.SecuritySnacksDomain
import com.security.scanner.external.integration.SecuritySnacksClient
import com.security.scanner.repository.SecuritySnacksRepository
import kotlinx.coroutines.runBlocking
import org.slf4j.LoggerFactory
import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.net.URI
import java.time.Instant
import java.util.concurrent.TimeUnit
import com.security.scanner.config.SecuritySnacksConfig

@Service
class SecuritySnacksIngestionService(
    private val client: SecuritySnacksClient,
    private val repository: SecuritySnacksRepository,
    private val redisTemplate: StringRedisTemplate,
    private val config: SecuritySnacksConfig
) {
    private val log = LoggerFactory.getLogger(javaClass)
    private val REDIS_PREFIX = "sec_snack:"
    private val CACHE_DAYS = 90L

    @Scheduled(cron = "\${security.snacks.cronSchedule:0 0 2 * * ?}")
    @Transactional
    fun ingestFeed() {
        log.info("Starting SecuritySnacks automated ingestion...")
        
        val discoveredFeeds = runBlocking { client.discoverCsvFeeds() }
        val allFeeds: List<String> = (config.feedUrls + discoveredFeeds).distinct()
        
        log.info("Discovered ${discoveredFeeds.size} feeds. Total feeds to process: ${allFeeds.size}")
        
        allFeeds.forEach { url: String ->
            log.info("Processing feed: $url")
            val csvData = runBlocking { client.fetchFeedData(url) }
            
            if (csvData != null) {
                processCsvData(csvData)
            } else {
                log.warn("Failed to fetch data from feed: $url")
            }
            // Small delay to be nice to GitHub API
            runBlocking { kotlinx.coroutines.delay(200) }
        }
        
        log.info("SecuritySnacks ingestion completed for all feeds.")
    }

    private fun processCsvData(csvData: String) {
        var count = 0
        for (line in csvData.lines()) {
            val domain = extractAndNormalizeDomain(line) ?: continue
            
            // Skip header if present
            if (domain == "domain") continue

            if (domain.length < 4 || domain.contains("localhost")) continue

            try {
                saveDomain(domain)
                count++
            } catch (e: Exception) {
                log.error("Failed to save domain $domain: ${e.message}")
            }
        }
        log.info("Processed $count domains from feed.")
    }

    private fun saveDomain(domain: String) {
        var entity = repository.findByDomain(domain)
        if (entity == null) {
            entity = SecuritySnacksDomain(domain = domain)
        } else {
            entity.lastSeenAt = Instant.now()
            entity.isActive = true
        }
        repository.save(entity)
        
        // Push to Redis Cache (90 days TTL)
        redisTemplate.opsForValue().set("$REDIS_PREFIX$domain", "true", CACHE_DAYS, TimeUnit.DAYS)
    }

    fun isDomainDangerous(url: String): Boolean {
        val domain = extractAndNormalizeDomain(url) ?: return false
        val isCached = redisTemplate.hasKey("$REDIS_PREFIX$domain")
        return isCached == true
    }

    private fun extractAndNormalizeDomain(raw: String): String? {
        val trimmed = raw.substringBefore(",").trim().lowercase()
        if (trimmed.isEmpty() || trimmed.startsWith("domain") || trimmed.startsWith("#")) return null
        
        return try {
            val uriStr = if (!trimmed.startsWith("http")) "http://$trimmed" else trimmed
            val uri = URI(uriStr)
            uri.host?.removePrefix("www.")
        } catch (e: Exception) {
            null
        }
    }
}
