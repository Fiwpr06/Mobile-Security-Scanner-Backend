package com.security.scanner.external.integration

import com.security.scanner.domain.dto.GoogleSafeBrowsingResult
import com.security.scanner.domain.dto.VirusTotalResult
import com.security.scanner.domain.dto.AbuseIpDbResult

/**
 * Port interface for threat intelligence providers.
 * Follows Hexagonal Architecture pattern.
 */
interface ThreatIntelligencePort {
    val sourceName: String
    val isEnabled: Boolean
    suspend fun analyze(url: String): ThreatAnalysisResult
}

data class ThreatAnalysisResult(
    val sourceName: String,
    val riskScore: Double,  // 0.0 - 100.0
    val isMalicious: Boolean,
    val rawData: Any?,
    val error: String? = null,
    val success: Boolean = true
)
