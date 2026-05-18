package com.security.scanner.service

import com.security.scanner.config.DatasetConfidenceConfig
import com.security.scanner.domain.model.RiskStatus
import com.security.scanner.repository.MaliciousUrlRepository
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

data class OfflineScanResult(
    val status: RiskStatus,
    val threatType: String?,
    val confidenceScore: Double,
    val fastReturn: Boolean,
    val skipExternalApis: Boolean
)

@Service
class OfflineThreatIntelService(
    private val bloomFilterService: BloomFilterService,
    private val redisCacheService: RedisThreatCacheService,
    private val domainReputationService: DomainReputationService,
    private val maliciousUrlRepository: MaliciousUrlRepository,
    private val config: DatasetConfidenceConfig
) {

    @Transactional(readOnly = true)
    fun evaluateUrl(canonicalData: CanonicalUrlData): OfflineScanResult {
        // 1. Domain Reputation Check
        if (bloomFilterService.mightContainDomain(canonicalData.normalizedDomain)) {
            if (domainReputationService.isDomainBlocked(canonicalData.normalizedDomain)) {
                return OfflineScanResult(
                    status = RiskStatus.DANGEROUS,
                    threatType = "MALICIOUS_DOMAIN",
                    confidenceScore = 1.0,
                    fastReturn = true,
                    skipExternalApis = true
                )
            }
        }

        // 2. Bloom Filter Check
        if (!bloomFilterService.mightContainUrlHash(canonicalData.urlHash)) {
            // High probability of being SAFE from offline perspective
            return OfflineScanResult(RiskStatus.SAFE, null, 0.0, false, false)
        }

        // 3. Redis Cache Check
        val cached = redisCacheService.getCachedUrlThreat(canonicalData.urlHash)
        if (cached != null) {
            return determineScanResult(cached.confidence, cached.threatType)
        }

        // 4. Database Check
        val dbMatch = maliciousUrlRepository.findByUrlHash(canonicalData.urlHash).orElse(null)
        if (dbMatch != null && dbMatch.isDangerous) {
            // Cache it for future
            redisCacheService.cacheDangerousUrl(canonicalData.urlHash, dbMatch.confidenceScore, dbMatch.threatCategory ?: "MALWARE")
            
            // Asynchronously update domain reputation
            domainReputationService.incrementDomainMaliciousCount(canonicalData.normalizedDomain)

            return determineScanResult(dbMatch.confidenceScore, dbMatch.threatCategory)
        }

        return OfflineScanResult(RiskStatus.SAFE, null, 0.0, false, false)
    }

    private fun determineScanResult(confidence: Double, threatType: String?): OfflineScanResult {
        return when {
            confidence >= config.dangerousThreshold -> {
                // High Confidence: Fast return immediately
                OfflineScanResult(RiskStatus.DANGEROUS, threatType, confidence, fastReturn = true, skipExternalApis = true)
            }
            confidence >= config.defaultWeight -> {
                // Medium Confidence: Don't fast return, but skip external APIs to save quota. Let heuristics/SSL decide.
                OfflineScanResult(RiskStatus.SUSPICIOUS, threatType, confidence, fastReturn = false, skipExternalApis = true)
            }
            else -> {
                // Low Confidence: Continue normal scan with external APIs
                OfflineScanResult(RiskStatus.UNKNOWN, threatType, confidence, fastReturn = false, skipExternalApis = false)
            }
        }
    }
}
