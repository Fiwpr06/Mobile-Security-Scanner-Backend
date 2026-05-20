package com.security.scanner.service

import com.security.scanner.config.ScanConfig
import com.security.scanner.domain.dto.*
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Service
import com.security.scanner.repository.DangerousDomainRepository
import org.springframework.data.domain.PageRequest

@Service
class ConfigService(
    private val scanConfig: ScanConfig,
    private val dangerousDomainRepository: DangerousDomainRepository,
    @Value("\${app.minimum-app-version:1.0.0}") private val minimumAppVersion: String,
    @Value("\${app.maintenance:false}") private val maintenance: Boolean,
    @Value("\${app.maintenance-message:}") private val maintenanceMessage: String
) {
    fun getAppConfig(): AppConfigResponse {
        return AppConfigResponse(
            weights = ScoringWeights(
                google = scanConfig.weights.googleSafeBrowsing,
                virusTotal = scanConfig.weights.virusTotal,
                abuseIpDb = scanConfig.weights.abuseIpDb
            ),
            thresholds = ScoringThresholds(
                safe = scanConfig.thresholds.safe,
                suspicious = scanConfig.thresholds.suspicious
            ),
            timeoutMs = maxOf(
                5000L,
                10000L,
                5000L
            ),
            maintenance = maintenance,
            maintenanceMessage = maintenanceMessage.ifBlank { null },
            minimumAppVersion = minimumAppVersion,
            featureFlags = mapOf(
                "parallelScan" to scanConfig.parallelEnabled,
                "fastFailOnDangerous" to scanConfig.fastFailOnDangerous,
                "cachingEnabled" to true,
                "reportingEnabled" to true
            ),
            offlineThreatList = dangerousDomainRepository.findAll(PageRequest.of(0, 1000)).map { it.domain }.toList()
        )
    }
}
