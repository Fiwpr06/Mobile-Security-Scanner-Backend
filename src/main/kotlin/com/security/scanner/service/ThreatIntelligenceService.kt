package com.security.scanner.service

import com.security.scanner.domain.dto.FalseNegativeReportRequest
import com.security.scanner.domain.dto.ReportResponse
import com.security.scanner.domain.dto.ThreatItem
import com.security.scanner.domain.dto.ThreatListResponse
import com.security.scanner.domain.model.FalseNegativeReport
import com.security.scanner.repository.FalseNegativeReportRepository
import com.security.scanner.repository.MaliciousUrlRepository
import org.slf4j.LoggerFactory
import org.springframework.data.domain.PageRequest
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class ThreatIntelligenceService(
    private val maliciousUrlRepository: MaliciousUrlRepository,
    private val falseNegativeReportRepository: FalseNegativeReportRepository
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
}
