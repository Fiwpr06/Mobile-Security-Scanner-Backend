package com.security.scanner.service

import com.security.scanner.common.BackgroundJobScope
import com.security.scanner.external.integration.SecuritySnacksClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.context.event.ApplicationReadyEvent
import org.springframework.context.event.EventListener
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Service
import java.io.File

@Service
class ThreatFeedScheduler(
    private val ingestionService: CsvThreatFeedIngestionService,
    private val securitySnacksClient: SecuritySnacksClient,
    private val bloomFilterService: BloomFilterService,
    private val backgroundJobScope: BackgroundJobScope,
    @Value("\${threat.intelligence.data.dir:data}") private val dataDir: String
) {
    private val log = LoggerFactory.getLogger(javaClass)

    @EventListener(ApplicationReadyEvent::class)
    fun onStartup() {
        log.info("Application ready. Triggering initial threat intelligence ingestion...")
        backgroundJobScope.launch {
            fetchFeedsAndIngest()
        }
    }

    @Scheduled(cron = "\${threat.intelligence.cronSchedule:0 0 3 * * ?}")
    fun scheduledIngestion() {
        log.info("Starting scheduled threat intelligence ingestion...")
        backgroundJobScope.launch {
            fetchFeedsAndIngest()
        }
    }

    private suspend fun fetchFeedsAndIngest() = withContext(Dispatchers.IO) {
        try {
            val dir = File(dataDir)
            if (!dir.exists()) {
                dir.mkdirs()
            }

            log.info("Discovering and downloading CSV feeds...")
            val feedUrls = securitySnacksClient.discoverCsvFeeds()
            for (url in feedUrls) {
                val csvContent = securitySnacksClient.fetchFeedData(url)
                if (!csvContent.isNullOrBlank()) {
                    val filename = url.substringAfterLast("/")
                    log.info("Processing downloaded feed $filename directly from memory...")
                    ingestionService.processContentIfNeeded(filename, csvContent)
                }
            }
        } catch (e: Exception) {
            log.error("Error fetching remote feeds: ${e.message}", e)
        }
        
        // Always run local directory ingestion
        ingestionService.ingestDirectory(dataDir)
    }
}
