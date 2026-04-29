package com.security.scanner.domain.dto

import com.security.scanner.domain.model.RiskStatus
import io.swagger.v3.oas.annotations.media.Schema
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size

// =============================================
// REQUEST DTOs
// =============================================

@Schema(description = "Device registration request")
data class DeviceRegistrationRequest(
    @field:NotBlank(message = "Device ID is required")
    @field:Size(min = 8, max = 256, message = "Device ID must be between 8 and 256 characters")
    @Schema(description = "Unique device identifier", example = "android-uuid-xxxx-xxxx")
    val deviceId: String,

    @Schema(description = "Device platform", example = "android")
    val platform: String? = null,

    @Schema(description = "App version", example = "1.0.0")
    val appVersion: String? = null
)

@Schema(description = "URL scan request")
data class ScanRequest(
    @field:NotBlank(message = "URL is required")
    @Schema(description = "URL to scan", example = "https://example.com")
    val url: String
)

@Schema(description = "False negative report request")
data class FalseNegativeReportRequest(
    @field:NotBlank(message = "URL is required")
    @Schema(description = "URL that was incorrectly marked as safe")
    val url: String,

    @field:NotBlank(message = "Original status is required")
    @Schema(description = "The status returned by the scanner", example = "SAFE")
    val originalStatus: String,

    val originalRiskScore: Int = 0,

    @Schema(description = "Optional user description of the threat")
    val userDescription: String? = null
)

// =============================================
// RESPONSE DTOs
// =============================================

@Schema(description = "Authentication response with JWT token")
data class AuthResponse(
    val accessToken: String,
    val tokenType: String = "Bearer",
    val expiresIn: Long,
    val deviceId: String
)

@Schema(description = "URL scan result")
data class ScanResponse(
    val url: String,
    val riskScore: Int,
    val status: RiskStatus,
    val sources: ScanSources,
    val scanTimeMs: Long,
    val isCached: Boolean = false,
    val scannedAt: String? = null
)

@Schema(description = "Scan results from each intelligence source")
data class ScanSources(
    val googleSafeBrowsing: GoogleSafeBrowsingResult? = null,
    val virusTotal: VirusTotalResult? = null,
    val abuseIpDb: AbuseIpDbResult? = null,
    val ssl: SslAnalysisResult? = null,
    val heuristic: HeuristicAnalysisResult? = null,
    val securitySnacksFlagged: Boolean = false
)

data class GoogleSafeBrowsingResult(
    val flagged: Boolean,
    val threatType: String? = null,
    val platformType: String? = null,
    val error: String? = null
)

data class VirusTotalResult(
    val malicious: Int = 0,
    val suspicious: Int = 0,
    val harmless: Int = 0,
    val undetected: Int = 0,
    val totalEngines: Int = 0,
    val permalink: String? = null,
    val error: String? = null
)

data class AbuseIpDbResult(
    val confidenceScore: Int = 0,
    val countryCode: String? = null,
    val domain: String? = null,
    val ipAddress: String? = null,
    val isTor: Boolean = false,
    val totalReports: Int = 0,
    val error: String? = null
)

data class SslAnalysisResult(
    val isValid: Boolean = true,
    val isExpired: Boolean = false,
    val isSelfSigned: Boolean = false,
    val isRevoked: Boolean = false,
    val invalidHostname: Boolean = false,
    val weakCipher: Boolean = false,
    val tlsVersion: String? = null,
    val cipherSuite: String? = null,
    val issuer: String? = null,
    val error: String? = null,
    val errorType: String? = null
)

data class HeuristicAnalysisResult(
    val riskScore: Int = 0,
    val findings: List<String> = emptyList(),
    val error: String? = null
)

@Schema(description = "Dynamic app configuration")
data class AppConfigResponse(
    val weights: ScoringWeights,
    val thresholds: ScoringThresholds,
    val timeoutMs: Long,
    val maintenance: Boolean,
    val maintenanceMessage: String?,
    val minimumAppVersion: String,
    val featureFlags: Map<String, Boolean>,
    val offlineThreatList: List<String> = emptyList()
)

data class ScoringWeights(
    val google: Double,
    val virusTotal: Double,
    val abuseIpDb: Double
)

data class ScoringThresholds(
    val safe: Int,
    val suspicious: Int
)

@Schema(description = "Top threat URLs")
data class ThreatListResponse(
    val threats: List<ThreatItem>,
    val total: Long,
    val page: Int,
    val pageSize: Int
)

data class ThreatItem(
    val url: String,
    val threatCategory: String?,
    val detectionCount: Long,
    val lastDetectedAt: String
)

@Schema(description = "Standard API error response")
data class ErrorResponse(
    val error: String,
    val message: String,
    val statusCode: Int,
    val timestamp: String,
    val path: String? = null,
    val requestId: String? = null
)

@Schema(description = "Standard success response")
data class SuccessResponse<T>(
    val success: Boolean = true,
    val data: T,
    val requestId: String? = null
)

data class ReportResponse(
    val reportId: String,
    val status: String,
    val message: String
)
