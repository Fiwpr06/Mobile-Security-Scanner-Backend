package com.security.scanner.service

import com.security.scanner.common.BackgroundJobScope
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.context.event.ApplicationReadyEvent
import org.springframework.context.event.EventListener
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Service

@Service
class ThreatFeedScheduler(
    private val ingestionService: CsvThreatFeedIngestionService,
    private val bloomFilterService: BloomFilterService,
    private val backgroundJobScope: BackgroundJobScope,
    @Value("\${threat.intelligence.data.dir:data}") private val dataDir: String
) {
    private val log = LoggerFactory.getLogger(javaClass)

    @EventListener(ApplicationReadyEvent::class)
    fun onStartup() {
        log.info("Application ready. Triggering initial threat intelligence ingestion...")
        backgroundJobScope.launch {
            ingestionService.ingestDirectory(dataDir)
        }
    }

    @Scheduled(cron = "\${threat.intelligence.cronSchedule:0 0 3 * * ?}")
    fun scheduledIngestion() {
        log.info("Starting scheduled threat intelligence ingestion...")
        backgroundJobScope.launch {
            ingestionService.ingestDirectory(dataDir)
        }
    }
}
