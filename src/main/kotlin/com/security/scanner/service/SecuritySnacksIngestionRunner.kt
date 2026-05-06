package com.security.scanner.service

import org.slf4j.LoggerFactory
import org.springframework.boot.CommandLineRunner
import org.springframework.stereotype.Component

@Component
class SecuritySnacksIngestionRunner(
    private val ingestionService: SecuritySnacksIngestionService
) : CommandLineRunner {
    private val log = LoggerFactory.getLogger(javaClass)

    override fun run(vararg args: String?) {
        log.info("Triggering initial SecuritySnacks ingestion...")
        try {
            ingestionService.ingestFeed()
            log.info("Initial SecuritySnacks ingestion triggered successfully.")
        } catch (e: Exception) {
            log.error("Failed to trigger initial SecuritySnacks ingestion: ${e.message}")
        }
    }
}
