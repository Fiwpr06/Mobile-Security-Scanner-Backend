package com.security.scanner.repository

import com.security.scanner.domain.model.MaliciousUrl
import org.springframework.data.domain.Page
import org.springframework.data.domain.Pageable
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Modifying
import org.springframework.data.jpa.repository.Query
import org.springframework.stereotype.Repository
import java.time.Instant
import java.util.Optional
import java.util.UUID

@Repository
interface MaliciousUrlRepository : JpaRepository<MaliciousUrl, UUID> {
    fun findByUrlHash(urlHash: String): Optional<MaliciousUrl>
    fun existsByUrlHash(urlHash: String): Boolean

    @Query("SELECT m FROM MaliciousUrl m ORDER BY m.detectionCount DESC")
    fun findTopThreats(pageable: Pageable): Page<MaliciousUrl>

    @Modifying
    @Query("UPDATE MaliciousUrl m SET m.detectionCount = m.detectionCount + 1, m.lastDetectedAt = :now WHERE m.urlHash = :urlHash")
    fun incrementDetectionCount(urlHash: String, now: Instant)
}
