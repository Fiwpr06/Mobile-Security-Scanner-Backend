package com.security.scanner.repository

import com.security.scanner.domain.model.MaliciousUrl
import org.springframework.data.domain.Page
import org.springframework.data.domain.Pageable
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Modifying
import org.springframework.data.jpa.repository.Query
import org.springframework.stereotype.Repository
import org.springframework.transaction.annotation.Transactional
import java.time.Instant
import java.util.Optional

@Repository
interface MaliciousUrlRepository : JpaRepository<MaliciousUrl, String> {
    fun findByUrlHash(urlHash: String): Optional<MaliciousUrl>
    fun existsByUrlHash(urlHash: String): Boolean

    @Query("SELECT m FROM MaliciousUrl m WHERE m.isDangerous = true")
    fun findTopThreats(pageable: Pageable): Page<MaliciousUrl>

    @Query("SELECT m FROM MaliciousUrl m WHERE m.isDangerous = true AND (LOWER(m.url) LIKE LOWER(CONCAT('%', :query, '%')) OR LOWER(m.normalizedDomain) LIKE LOWER(CONCAT('%', :query, '%')))")
    fun searchThreats(query: String, pageable: Pageable): Page<MaliciousUrl>

    @Modifying
    @Transactional
    @Query("UPDATE MaliciousUrl m SET m.detectionCount = m.detectionCount + 1, m.lastDetectedAt = :now WHERE m.urlHash = :urlHash")
    fun incrementDetectionCount(urlHash: String, now: Instant)

    @Modifying
    @Transactional
    @Query(value = """
        INSERT INTO malicious_urls (
            url_hash, url, normalized_domain, normalized_path, threat_category, 
            is_dangerous, confidence_score, detection_count, first_detected_at, 
            last_detected_at, sources
        ) VALUES (
            :#{#m.urlHash}, :#{#m.url}, :#{#m.normalizedDomain}, :#{#m.normalizedPath}, :#{#m.threatCategory},
            :#{#m.isDangerous}, :#{#m.confidenceScore}, :#{#m.detectionCount}, :#{#m.firstDetectedAt},
            :#{#m.lastDetectedAt}, :#{#m.sources}
        ) ON CONFLICT (url_hash) DO UPDATE SET 
            threat_category = CASE WHEN EXCLUDED.confidence_score > malicious_urls.confidence_score THEN EXCLUDED.threat_category ELSE malicious_urls.threat_category END,
            is_dangerous = CASE WHEN EXCLUDED.confidence_score > malicious_urls.confidence_score THEN EXCLUDED.is_dangerous ELSE malicious_urls.is_dangerous END,
            confidence_score = GREATEST(malicious_urls.confidence_score, EXCLUDED.confidence_score),
            detection_count = malicious_urls.detection_count + EXCLUDED.detection_count,
            last_detected_at = GREATEST(malicious_urls.last_detected_at, EXCLUDED.last_detected_at),
            sources = malicious_urls.sources || ',' || EXCLUDED.sources
    """, nativeQuery = true)
    fun upsertMaliciousUrl(m: MaliciousUrl)
}
