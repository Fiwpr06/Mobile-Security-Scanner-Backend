package com.security.scanner.service

import com.security.scanner.config.ScanConfig
import com.security.scanner.domain.dto.*
import com.security.scanner.domain.model.MaliciousUrl
import com.security.scanner.domain.model.RiskStatus
import com.security.scanner.domain.model.ScanResult
import com.security.scanner.external.integration.*
import com.security.scanner.heuristic.HeuristicAnalyzer
import com.security.scanner.repository.MaliciousUrlRepository
import com.security.scanner.repository.ScanResultRepository
import com.security.scanner.ssl.SslAnalyzer
import com.security.scanner.service.SecuritySnacksIngestionService
import kotlinx.coroutines.*
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.security.MessageDigest
import java.time.Instant

@Service
class ScanEngineService(
    private val googleSafeBrowsingClient: GoogleSafeBrowsingClient,
    private val virusTotalClient: VirusTotalClient,
    private val abuseIpDbClient: AbuseIpDbClient,
    private val scanResultRepository: ScanResultRepository,
    private val maliciousUrlRepository: MaliciousUrlRepository,
    private val scanConfig: ScanConfig,
    private val sslAnalyzer: SslAnalyzer,
    private val heuristicAnalyzer: HeuristicAnalyzer,
    private val securitySnacksService: SecuritySnacksIngestionService
) {
    private val log = LoggerFactory.getLogger(javaClass)

    @Transactional
    suspend fun scanUrl(url: String, deviceId: String): ScanResponse {
        val startTime = System.currentTimeMillis()
        val urlHash = hashUrl(url)

        val cached = findRecentScan(urlHash)
        if (cached != null) {
            log.info("Returning cached result for url hash=$urlHash")
            // Run local analyzers on the fly for cached results since they aren't stored in DB yet
            val sslResult = sslAnalyzer.analyze(url)
            val heuristicResult = heuristicAnalyzer.analyze(url)
            val inSecuritySnacks = securitySnacksService.isDomainDangerous(url)
            return cached.toResponse(isCached = true, sslResult = sslResult, heuristicResult = heuristicResult, inSecuritySnacks = inSecuritySnacks)
        }

        val results = if (scanConfig.parallelEnabled) {
            runParallelScan(url)
        } else {
            runSequentialScan(url)
        }

        // Run local analyzers
        val sslResult = sslAnalyzer.analyze(url)
        val heuristicResult = heuristicAnalyzer.analyze(url)

        val scanTimeMs = System.currentTimeMillis() - startTime
        val aggregated = aggregateResults(url, results, sslResult, heuristicResult, scanTimeMs, deviceId, urlHash)

        if (aggregated.status == RiskStatus.DANGEROUS) {
            persistMaliciousUrl(url, urlHash, results)
        }

        saveScanResult(aggregated, deviceId, urlHash, scanTimeMs, results)
        log.info("Scan completed url=$url status=${aggregated.status} score=${aggregated.riskScore} time=${scanTimeMs}ms")

        return aggregated.copy(scanTimeMs = scanTimeMs)
    }

    private suspend fun runParallelScan(url: String): Map<String, ThreatAnalysisResult> = coroutineScope {
        if (scanConfig.fastFailOnDangerous) {
            val googleResult = googleSafeBrowsingClient.analyze(url)
            if (googleResult.isMalicious) {
                log.info("Fast-fail: Google Safe Browsing flagged URL as dangerous, stopping scan")
                val vtDeferred = async { virusTotalClient.analyze(url) }
                val abuseDeferred = async { abuseIpDbClient.analyze(url) }
                return@coroutineScope mapOf(
                    googleSafeBrowsingClient.sourceName to googleResult,
                    virusTotalClient.sourceName to virusTotalClient.analyze(url),
                    abuseIpDbClient.sourceName to abuseIpDbClient.analyze(url)
                )
            }
        }

        val googleDeferred = async { googleSafeBrowsingClient.analyze(url) }
        val vtDeferred = async { virusTotalClient.analyze(url) }
        val abuseDeferred = async { abuseIpDbClient.analyze(url) }

        mapOf(
            googleSafeBrowsingClient.sourceName to googleDeferred.await(),
            virusTotalClient.sourceName to vtDeferred.await(),
            abuseIpDbClient.sourceName to abuseDeferred.await()
        )
    }

    private suspend fun runSequentialScan(url: String): Map<String, ThreatAnalysisResult> {
        val results = mutableMapOf<String, ThreatAnalysisResult>()
        results[googleSafeBrowsingClient.sourceName] = googleSafeBrowsingClient.analyze(url)
        results[virusTotalClient.sourceName] = virusTotalClient.analyze(url)
        results[abuseIpDbClient.sourceName] = abuseIpDbClient.analyze(url)
        return results
    }

    private fun aggregateResults(
        url: String,
        results: Map<String, ThreatAnalysisResult>,
        sslResult: SslAnalysisResult,
        heuristicResult: HeuristicAnalysisResult,
        scanTimeMs: Long,
        deviceId: String,
        urlHash: String
    ): ScanResponse {
        var score = 0
        var apiFailures = 0
        var allApisFailed = true

        // 1. Local High Confidence Threat Intel (SecuritySnacks)
        val inSecuritySnacks = securitySnacksService.isDomainDangerous(url)
        if (inSecuritySnacks) {
            score += 100 // Immediate DANGEROUS status
        }

        val googleResult = results[googleSafeBrowsingClient.sourceName]
        if (googleResult != null && googleResult.success) {
            allApisFailed = false
            if (googleResult.isMalicious) score += 80
        } else {
            apiFailures++
        }

        val vtResult = results[virusTotalClient.sourceName]
        if (vtResult != null && vtResult.success) {
            allApisFailed = false
            val vtData = vtResult.rawData as? VirusTotalResult
            if (vtData != null) {
                if (vtData.malicious > 0) score += 90
                if (vtData.suspicious > 0) score += 50
            }
        } else {
            apiFailures++
        }

        val abuseResult = results[abuseIpDbClient.sourceName]
        if (abuseResult != null && abuseResult.success) {
            allApisFailed = false
            val abuseData = abuseResult.rawData as? AbuseIpDbResult
            if (abuseData != null) {
                if (abuseData.confidenceScore > 50) score += 50
            }
        } else {
            apiFailures++
        }

        // Penalty for API Failures (Fail-Open fix)
        score += apiFailures * 15

        // SSL Scores
        if (sslResult.isExpired) score += 40
        if (sslResult.isRevoked) score += 70
        if (sslResult.isSelfSigned) score += 35
        if (sslResult.invalidHostname) score += 30
        if (sslResult.weakCipher) score += 20

        // Heuristic Scores
        score += heuristicResult.riskScore

        val finalScore = score.coerceIn(0, 100)

        // Status determination
        val status = when {
            finalScore >= scanConfig.thresholds.suspicious -> RiskStatus.DANGEROUS
            finalScore >= scanConfig.thresholds.safe -> RiskStatus.SUSPICIOUS
            allApisFailed -> RiskStatus.UNKNOWN
            apiFailures >= 2 && finalScore < scanConfig.thresholds.safe -> RiskStatus.UNKNOWN
            else -> RiskStatus.SAFE
        }

        return ScanResponse(
            url = url,
            riskScore = finalScore,
            status = status,
            sources = buildSources(results, sslResult, heuristicResult, inSecuritySnacks),
            scanTimeMs = scanTimeMs
        )
    }

    private fun buildSources(
        results: Map<String, ThreatAnalysisResult>,
        sslResult: SslAnalysisResult,
        heuristicResult: HeuristicAnalysisResult,
        inSecuritySnacks: Boolean
    ): ScanSources {
        val google = results[googleSafeBrowsingClient.sourceName]?.rawData as? GoogleSafeBrowsingResult
        val vt = results[virusTotalClient.sourceName]?.rawData as? VirusTotalResult
        val abuse = results[abuseIpDbClient.sourceName]?.rawData as? AbuseIpDbResult

        return ScanSources(
            googleSafeBrowsing = google ?: results[googleSafeBrowsingClient.sourceName]?.error?.let {
                GoogleSafeBrowsingResult(flagged = false, error = it)
            },
            virusTotal = vt ?: results[virusTotalClient.sourceName]?.error?.let {
                VirusTotalResult(error = it)
            },
            abuseIpDb = abuse ?: results[abuseIpDbClient.sourceName]?.error?.let {
                AbuseIpDbResult(error = it)
            },
            ssl = sslResult,
            heuristic = heuristicResult,
            securitySnacksFlagged = inSecuritySnacks
        )
    }

    private fun findRecentScan(urlHash: String): ScanResult? {
        return scanResultRepository.findTopByUrlHashOrderByScannedAtDesc(urlHash)
            .filter { it.scannedAt.isAfter(Instant.now().minusSeconds(300)) } // 5 min cache
            .orElse(null)
    }

    private fun saveScanResult(
        response: ScanResponse,
        deviceId: String,
        urlHash: String,
        scanTimeMs: Long,
        results: Map<String, ThreatAnalysisResult>
    ): ScanResult {
        val google = results[googleSafeBrowsingClient.sourceName]?.rawData as? GoogleSafeBrowsingResult
        val vt = results[virusTotalClient.sourceName]?.rawData as? VirusTotalResult
        val abuse = results[abuseIpDbClient.sourceName]?.rawData as? AbuseIpDbResult

        val entity = ScanResult(
            url = response.url,
            urlHash = urlHash,
            deviceId = deviceId,
            riskScore = response.riskScore,
            status = response.status,
            googleSafeBrowsingFlagged = google?.flagged,
            googleThreatType = google?.threatType,
            virusTotalMalicious = vt?.malicious,
            virusTotalSuspicious = vt?.suspicious,
            virusTotalTotalEngines = vt?.totalEngines,
            abuseIpDbConfidenceScore = abuse?.confidenceScore,
            abuseIpDbCountryCode = abuse?.countryCode,
            scanTimeMs = scanTimeMs
        )
        return scanResultRepository.save(entity)
    }

    private fun persistMaliciousUrl(url: String, urlHash: String, results: Map<String, ThreatAnalysisResult>) {
        val sources = results.filter { it.value.isMalicious }.keys.joinToString(",")
        if (maliciousUrlRepository.existsByUrlHash(urlHash)) {
            maliciousUrlRepository.incrementDetectionCount(urlHash, Instant.now())
        } else {
            maliciousUrlRepository.save(
                MaliciousUrl(
                    url = url,
                    urlHash = urlHash,
                    sources = sources,
                    threatCategory = determineThreatCategory(results)
                )
            )
        }
    }

    private fun determineThreatCategory(results: Map<String, ThreatAnalysisResult>): String? {
        val google = results[googleSafeBrowsingClient.sourceName]?.rawData as? GoogleSafeBrowsingResult
        return google?.threatType ?: "UNKNOWN"
    }

    private fun hashUrl(url: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(url.toByteArray())
        return hash.joinToString("") { "%02x".format(it) }
    }

    private fun ScanResult.toResponse(
        isCached: Boolean, 
        sslResult: SslAnalysisResult? = null, 
        heuristicResult: HeuristicAnalysisResult? = null,
        inSecuritySnacks: Boolean = false
    ): ScanResponse = ScanResponse(
        url = this.url,
        riskScore = this.riskScore,
        status = this.status,
        sources = ScanSources(
            googleSafeBrowsing = this.googleSafeBrowsingFlagged?.let {
                GoogleSafeBrowsingResult(flagged = it, threatType = this.googleThreatType)
            },
            virusTotal = this.virusTotalMalicious?.let {
                VirusTotalResult(
                    malicious = it,
                    suspicious = this.virusTotalSuspicious ?: 0,
                    totalEngines = this.virusTotalTotalEngines ?: 0
                )
            },
            abuseIpDb = this.abuseIpDbConfidenceScore?.let {
                AbuseIpDbResult(confidenceScore = it, countryCode = this.abuseIpDbCountryCode)
            },
            ssl = sslResult,
            heuristic = heuristicResult,
            securitySnacksFlagged = inSecuritySnacks
        ),
        scanTimeMs = this.scanTimeMs,
        isCached = isCached,
        scannedAt = this.scannedAt.toString()
    )
}
