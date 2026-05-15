package com.security.scanner.common

import jakarta.annotation.PreDestroy
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Component
import kotlin.coroutines.CoroutineContext

/**
 * A lifecycle-aware CoroutineScope for running background jobs (like CSV ingestion).
 * Replaces the dangerous GlobalScope.launch anti-pattern.
 * Ensures that if the application context is closed, all background jobs are properly cancelled.
 */
@Component
class BackgroundJobScope : CoroutineScope {
    private val log = LoggerFactory.getLogger(javaClass)

    private val job = SupervisorJob()

    private val exceptionHandler = CoroutineExceptionHandler { _, throwable ->
        log.error("Background job failed with exception", throwable)
    }

    override val coroutineContext: CoroutineContext
        get() = Dispatchers.IO + job + exceptionHandler

    @PreDestroy
    fun close() {
        log.info("Application shutting down. Cancelling background coroutine jobs...")
        job.cancel("Application shutting down")
    }
}
