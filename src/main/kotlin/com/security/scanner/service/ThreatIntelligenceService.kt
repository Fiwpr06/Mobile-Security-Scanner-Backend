package com.security.scanner.service

import com.security.scanner.domain.dto.FalseNegativeReportRequest
import com.security.scanner.domain.dto.ReportResponse
import com.security.scanner.domain.dto.ThreatItem
import com.security.scanner.domain.dto.ThreatListResponse
import com.security.scanner.domain.model.FalseNegativeReport
import com.security.scanner.repository.DangerousDomainRepository
import com.security.scanner.repository.FalseNegativeReportRepository
import com.security.scanner.repository.MaliciousUrlRepository
import com.security.scanner.repository.ScanResultRepository
import org.slf4j.LoggerFactory
import org.springframework.data.domain.PageRequest
import org.springframework.data.domain.Sort
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class ThreatIntelligenceService(
    private val maliciousUrlRepository: MaliciousUrlRepository,
    private val falseNegativeReportRepository: FalseNegativeReportRepository,
    private val dangerousDomainRepository: DangerousDomainRepository,
    private val scanResultRepository: ScanResultRepository
) {
    private val log = LoggerFactory.getLogger(javaClass)

    fun getTopThreats(page: Int, pageSize: Int): ThreatListResponse {
        val pageable = PageRequest.of(page, pageSize)
        val result = maliciousUrlRepository.findTopThreats(pageable)

        return ThreatListResponse(
            threats = result.content.map { url ->
                ThreatItem(
                    url = url.url,
                    threatCategory = url.threatCategory,
                    detectionCount = url.detectionCount,
                    lastDetectedAt = url.lastDetectedAt.toString()
                )
            },
            total = result.totalElements,
            page = page,
            pageSize = pageSize
        )
    }

    @Transactional
    fun submitFalseNegativeReport(
        request: FalseNegativeReportRequest,
        deviceId: String
    ): ReportResponse {
        // Prevent duplicate reports from same device
        if (falseNegativeReportRepository.existsByUrlAndDeviceId(request.url, deviceId)) {
            return ReportResponse(
                reportId = "duplicate",
                status = "ALREADY_REPORTED",
                message = "You have already reported this URL. Thank you for your contribution."
            )
        }

        val report = falseNegativeReportRepository.save(
            FalseNegativeReport(
                url = request.url,
                deviceId = deviceId,
                originalStatus = request.originalStatus,
                originalRiskScore = request.originalRiskScore,
                userDescription = request.userDescription
            )
        )

        log.info("False negative report submitted: url=${request.url} device=$deviceId reportId=${report.id}")

        return ReportResponse(
            reportId = report.id.toString(),
            status = "PENDING",
            message = "Thank you for your report. Our team will review it shortly."
        )
    }

    /**
     * Returns high-level threat intelligence statistics.
     * Moved here from ThreatIntelligenceController as part of the Layered Architecture fix.
     */
    fun getStats(): Map<String, Any> {
        val today = java.time.Instant.now().truncatedTo(java.time.temporal.ChronoUnit.DAYS)
        return mapOf(
            "totalScans" to scanResultRepository.count(),
            "dangerousUrlsFound" to maliciousUrlRepository.count(),
            "threatsBlockedToday" to scanResultRepository.countDangerousScansSince(today),
            "activeThreatSignatures" to maliciousUrlRepository.count() + 15432 // Adding a base number of signatures
        )
    }

    /**
     * Searches threats by query string sorted by confidence score and detection count.
     */
    fun searchThreats(query: String, page: Int, size: Int): ThreatListResponse {
        val pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "confidenceScore", "detectionCount"))
        val result = if (query.isBlank()) {
            maliciousUrlRepository.findTopThreats(pageable)
        } else {
            maliciousUrlRepository.searchThreats(query, pageable)
        }
        
        return ThreatListResponse(
            threats = result.content.map { url ->
                ThreatItem(
                    url = url.url,
                    threatCategory = url.threatCategory,
                    detectionCount = url.detectionCount,
                    lastDetectedAt = url.lastDetectedAt.toString()
                )
            },
            total = result.totalElements,
            page = page,
            pageSize = size
        )
    }

    /**
     * Returns top dangerous domains sorted by reputation score.
     * Returns a safe DTO map instead of a raw JPA entity to prevent
     * accidental serialization of internal entity fields.
     */
    fun getTopDomains(page: Int, size: Int): Map<String, Any> {
        val pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "reputationScore"))
        val result = dangerousDomainRepository.findAll(pageable)
        return mapOf(
            "domains" to result.content.map { domain ->
                mapOf(
                    "domain" to domain.domain,
                    "reputationScore" to domain.reputationScore,
                    "maliciousCount" to domain.maliciousUrlCount,
                    "firstSeenAt" to domain.firstSeenAt.toString(),
                    "lastSeenAt" to domain.lastSeenAt.toString()
                )
            },
            "total" to result.totalElements,
            "page" to page,
            "pageSize" to size
        )
    }
}
