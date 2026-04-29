package com.security.scanner.domain.model

import jakarta.persistence.*
import java.time.Instant
import java.util.UUID

@Entity
@Table(name = "malicious_urls")
data class MaliciousUrl(
    @Id
    @Column(name = "id", nullable = false)
    val id: UUID = UUID.randomUUID(),

    @Column(name = "url", nullable = false, columnDefinition = "TEXT")
    val url: String,

    @Column(name = "url_hash", nullable = false, unique = true)
    val urlHash: String,

    @Column(name = "threat_category")
    val threatCategory: String? = null,

    @Column(name = "detection_count", nullable = false)
    var detectionCount: Long = 1L,

    @Column(name = "last_detected_at", nullable = false)
    var lastDetectedAt: Instant = Instant.now(),

    @Column(name = "first_detected_at", nullable = false)
    val firstDetectedAt: Instant = Instant.now(),

    @Column(name = "sources", columnDefinition = "TEXT")
    val sources: String? = null // JSON list of sources
)
