package com.security.scanner.repository

import com.security.scanner.domain.model.ScanResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import java.time.Instant

/**
 * Adapter to isolate blocking JPA calls from the business logic.
 * This ensures that Dispatchers.IO does not leak throughout the service layer
 * and keeps the transaction boundaries strictly isolated to the DB thread.
 */
@Repository
class ScanRepositoryAdapter(
    private val repository: ScanResultRepository
) {

    suspend fun findRecent(urlHash: String): ScanResult? =
        withContext(Dispatchers.IO) {
            repository.findTopByUrlHashOrderByScannedAtDesc(urlHash)
                .filter { it.scannedAt.isAfter(Instant.now().minusSeconds(300)) }
                .orElse(null)
        }

    /**
     * Executes the DB save in the IO dispatcher with a dedicated transaction.
     * The @Transactional annotation is placed here to ensure the connection
     * is only held during this blocking IO operation.
     */
    @Transactional
    suspend fun save(entity: ScanResult): ScanResult =
        withContext(Dispatchers.IO) {
            repository.save(entity)
        }
}
