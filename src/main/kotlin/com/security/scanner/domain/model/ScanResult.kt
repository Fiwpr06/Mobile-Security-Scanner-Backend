package com.security.scanner.domain.model

import jakarta.persistence.*
import java.time.Instant
import java.util.UUID

enum class RiskStatus {
    SAFE, SUSPICIOUS, DANGEROUS, UNKNOWN
}

@Entity
@Table(name = "scan_results")
data class ScanResult(
    @Id
    @Column(name = "id", nullable = false)
    val id: UUID = UUID.randomUUID(),

    @Column(name = "url", nullable = false, columnDefinition = "TEXT")
    val url: String,

    @Column(name = "url_hash", nullable = false)
    val urlHash: String,

    @Column(name = "device_id", nullable = false)
    val deviceId: String,

    @Column(name = "user_id")
    var userId: UUID? = null,

    @Column(name = "risk_score", nullable = false)
    val riskScore: Int,

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    val status: RiskStatus,

    @Column(name = "google_safe_browsing_flagged")
    val googleSafeBrowsingFlagged: Boolean? = null,

    @Column(name = "google_threat_type", columnDefinition = "TEXT")
    val googleThreatType: String? = null,

    @Column(name = "virus_total_malicious")
    val virusTotalMalicious: Int? = null,

    @Column(name = "virus_total_suspicious")
    val virusTotalSuspicious: Int? = null,

    @Column(name = "virus_total_total_engines")
    val virusTotalTotalEngines: Int? = null,

    @Column(name = "abuse_ipdb_confidence_score")
    val abuseIpDbConfidenceScore: Int? = null,

    @Column(name = "abuse_ipdb_country_code")
    val abuseIpDbCountryCode: String? = null,

    @Column(name = "scan_time_ms", nullable = false)
    val scanTimeMs: Long,

    @Column(name = "scanned_at", nullable = false)
    val scannedAt: Instant = Instant.now(),

    @Column(name = "is_cached", nullable = false)
    val isCached: Boolean = false,

    @Column(name = "error_message", columnDefinition = "TEXT")
    val errorMessage: String? = null
)
