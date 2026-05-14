package com.security.scanner.domain.model

import jakarta.persistence.*
import java.time.Instant

@Entity
@Table(name = "malicious_urls", indexes = [
    Index(name = "idx_malicious_urls_domain", columnList = "normalized_domain"),
    Index(name = "idx_malicious_urls_threat", columnList = "threat_category"),
    Index(name = "idx_malicious_urls_dangerous", columnList = "is_dangerous")
])
data class MaliciousUrl(
    @Id
    @Column(name = "url_hash", nullable = false, unique = true, length = 64)
    val urlHash: String,

    @Column(name = "url", nullable = false, columnDefinition = "TEXT")
    val url: String, // Original or fully canonicalized URL string

    @Column(name = "normalized_domain", nullable = false)
    val normalizedDomain: String,

    @Column(name = "normalized_path", nullable = false, columnDefinition = "TEXT")
    val normalizedPath: String,

    @Column(name = "threat_category")
    var threatCategory: String? = null,

    @Column(name = "is_dangerous", nullable = false)
    var isDangerous: Boolean = false,

    @Column(name = "confidence_score", nullable = false)
    var confidenceScore: Double = 0.0,

    @Column(name = "detection_count", nullable = false)
    var detectionCount: Long = 1L,

    @Column(name = "first_detected_at", nullable = false)
    val firstDetectedAt: Instant = Instant.now(),

    @Column(name = "last_detected_at", nullable = false)
    var lastDetectedAt: Instant = Instant.now(),

    @Column(name = "sources", columnDefinition = "TEXT")
    var sources: String? = null // Comma separated or JSON
)
