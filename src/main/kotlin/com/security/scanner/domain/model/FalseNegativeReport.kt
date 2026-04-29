package com.security.scanner.domain.model

import jakarta.persistence.*
import java.time.Instant
import java.util.UUID

enum class ReportStatus {
    PENDING, REVIEWED, CONFIRMED_THREAT, DISMISSED
}

@Entity
@Table(name = "false_negative_reports")
data class FalseNegativeReport(
    @Id
    @Column(name = "id", nullable = false)
    val id: UUID = UUID.randomUUID(),

    @Column(name = "url", nullable = false, columnDefinition = "TEXT")
    val url: String,

    @Column(name = "device_id", nullable = false)
    val deviceId: String,

    @Column(name = "original_status", nullable = false)
    val originalStatus: String,

    @Column(name = "original_risk_score", nullable = false)
    val originalRiskScore: Int,

    @Column(name = "user_description", columnDefinition = "TEXT")
    val userDescription: String? = null,

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    var status: ReportStatus = ReportStatus.PENDING,

    @Column(name = "reported_at", nullable = false)
    val reportedAt: Instant = Instant.now(),

    @Column(name = "reviewed_at")
    var reviewedAt: Instant? = null,

    @Column(name = "reviewer_notes", columnDefinition = "TEXT")
    var reviewerNotes: String? = null
)
