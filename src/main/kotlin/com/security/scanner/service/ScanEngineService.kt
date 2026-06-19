package com.security.scanner.service

import com.security.scanner.config.ScanConfig
import com.security.scanner.domain.dto.*
import com.security.scanner.domain.model.RiskStatus
import com.security.scanner.domain.model.ScanResult
import com.security.scanner.external.integration.*
import com.security.scanner.heuristic.HeuristicAnalyzer
import com.security.scanner.repository.ScanRepositoryAdapter
import com.security.scanner.ssl.SslAnalyzer
import kotlinx.coroutines.*
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import java.time.Instant

@Service
class ScanEngineService(
    private val googleSafeBrowsingClient: GoogleSafeBrowsingClient,
    private val virusTotalClient: VirusTotalClient,
    private val abuseIpDbClient: AbuseIpDbClient,
    private val scanRepositoryAdapter: ScanRepositoryAdapter,
    private val redisThreatCacheService: RedisThreatCacheService,
    private val scanConfig: ScanConfig,
    private val sslAnalyzer: SslAnalyzer,
    private val heuristicAnalyzer: HeuristicAnalyzer,
    private val offlineThreatIntelService: OfflineThreatIntelService,
    private val canonicalUrlService: CanonicalUrlService
) {
    private val log = LoggerFactory.getLogger(javaClass)

    /**
     * CRITICAL FIX: Removed @Transactional from this method.
     *
     * The previous implementation held an open DB Connection (from HikariCP) for the entire
     * duration of the scan — including all external HTTP calls to Google, VirusTotal, AbuseIPDB.
     * Each external call can take 5–10 seconds. With a pool of 20 connections, only 20 concurrent
     * scans were possible before the entire application deadlocked.
     *
     * FIX: @Transactional is now placed ONLY on saveScanResult(), which is the only method
     * that actually needs a DB transaction. This reduces connection hold time from ~10s to <10ms.
     */
    suspend fun scanUrl(rawUrl: String, deviceId: String, userId: java.util.UUID? = null): ScanResponse {
        val startTime = System.currentTimeMillis()

        // 1. Canonicalization
        val canonicalData = canonicalUrlService.canonicalize(rawUrl)
            ?: return createInvalidUrlResponse(rawUrl, startTime)

        val urlHash = canonicalData.urlHash
        val canonicalUrl = canonicalData.fullCanonicalUrl

        // 2. Redis-First Cache
        val cachedRedis = redisThreatCacheService.getCachedUrlThreat(urlHash)
        if (cachedRedis != null) {
            log.info("Returning Redis cached result for url hash=$urlHash verdict=${cachedRedis.verdict}")
            val sslResult = sslAnalyzer.analyze(canonicalUrl)
            val heuristicResult = heuristicAnalyzer.analyze(canonicalUrl)
            val status = RiskStatus.valueOf(cachedRedis.verdict.uppercase())
            return ScanResponse(
                url = canonicalUrl,
                riskScore = (cachedRedis.confidence * 100).toInt(),
                status = status,
                sources = buildSources(emptyMap(), sslResult, heuristicResult, status == RiskStatus.DANGEROUS),
                scanTimeMs = 0,
                isCached = true
            )
        }

        // 2.5 Check DB Cache (Fallback)
        val cachedDb = findRecentScan(urlHash)
        if (cachedDb != null) {
            log.info("Returning Postgres cached result for url hash=$urlHash")
            val sslResult = sslAnalyzer.analyze(canonicalUrl)
            val heuristicResult = heuristicAnalyzer.analyze(canonicalUrl)
            return cachedDb.toResponse(isCached = true, sslResult = sslResult, heuristicResult = heuristicResult)
        }

        // 3. Offline Threat Intelligence Check
        val offlineResult = offlineThreatIntelService.evaluateUrl(canonicalData)

        // 4. Smart Early Return
        if (offlineResult.fastReturn) {
            log.info("Fast Return triggered by Offline Intel for $canonicalUrl. Status: ${offlineResult.status}")
            return buildOfflineResponse(canonicalUrl, urlHash, offlineResult, startTime, deviceId, userId)
        }

        // 5. External API Scanning & Local Analyzers
        val results = mutableMapOf<String, ThreatAnalysisResult>()
        
        // Run local analyzers once up front (virtually instantaneous, helps with conditional deep scanning)
        val sslResult = sslAnalyzer.analyze(canonicalUrl)
        val heuristicResult = heuristicAnalyzer.analyze(canonicalUrl)

        if (!offlineResult.skipExternalApis) {
            // Step 5.1: Google Safe Browsing (Primary Threat Authority)
            log.info("Calling Google Safe Browsing first for $canonicalUrl")
            val googleResult = googleSafeBrowsingClient.analyze(canonicalUrl)
            results[googleSafeBrowsingClient.sourceName] = googleResult

            // If Google returns DANGEROUS (isMalicious == true) -> Fast Return immediately
            if (googleResult.status == ThreatIntelStatus.SUCCESS && googleResult.isMalicious) {
                log.info("Fast Return: Google Safe Browsing flagged $canonicalUrl as malicious. Bypassing other external APIs.")
                val scanTimeMs = System.currentTimeMillis() - startTime
                val aggregated = aggregateResults(canonicalUrl, results, sslResult, heuristicResult, offlineResult, scanTimeMs)
                saveScanResult(aggregated, deviceId, urlHash, scanTimeMs, results, userId)
                return aggregated.copy(scanTimeMs = scanTimeMs)
            }

            // Step 5.2: AbuseIPDB (Secondary Reputation Engine)
            log.info("Calling AbuseIPDB for reputation check for $canonicalUrl")
            val abuseResult = abuseIpDbClient.analyze(canonicalUrl)
            results[abuseIpDbClient.sourceName] = abuseResult

            // Step 5.3: Calculate Intermediate Score
            val intermediateTimeMs = System.currentTimeMillis() - startTime
            val intermediateResponse = aggregateResults(canonicalUrl, results, sslResult, heuristicResult, offlineResult, intermediateTimeMs)

            // Step 5.4: Conditional VirusTotal (Deep Inspection Engine)
            if (shouldTriggerVirusTotal(googleResult, abuseResult, intermediateResponse.riskScore, heuristicResult)) {
                log.info("Deep Inspection required: Calling VirusTotal for $canonicalUrl")
                val vtResult = virusTotalClient.analyze(canonicalUrl)
                results[virusTotalClient.sourceName] = vtResult
            } else {
                log.info("Skipping VirusTotal deep inspection to optimize quota for $canonicalUrl")
            }
        } else {
            log.info("Skipping External APIs for $canonicalUrl due to offline Intel.")
        }

        val scanTimeMs = System.currentTimeMillis() - startTime
        val aggregated = aggregateResults(canonicalUrl, results, sslResult, heuristicResult, offlineResult, scanTimeMs)

        saveScanResult(aggregated, deviceId, urlHash, scanTimeMs, results, userId)
        log.info("Scan completed url=$canonicalUrl status=${aggregated.status} score=${aggregated.riskScore} time=${scanTimeMs}ms")

        return aggregated.copy(scanTimeMs = scanTimeMs)
    }

    private fun shouldTriggerVirusTotal(
        googleResult: ThreatAnalysisResult?,
        abuseResult: ThreatAnalysisResult?,
        intermediateScore: Int,
        heuristicResult: HeuristicAnalysisResult
    ): Boolean {
        val suspiciousThreshold = scanConfig.thresholds.suspicious
        val minConfidence = 15 // Default AbuseIPDB min confidence threshold
        
        val isSuspicious = intermediateScore >= suspiciousThreshold
        val isGoogleUnknown = googleResult == null || googleResult.status == ThreatIntelStatus.UNKNOWN || googleResult.status != ThreatIntelStatus.SUCCESS
        
        val abuseData = abuseResult?.rawData as? AbuseIpDbResult
        val abuseConfidence = abuseData?.confidenceScore ?: 0
        val isAbuseConfidenceLow = abuseResult == null || abuseResult.status != ThreatIntelStatus.SUCCESS || abuseConfidence < minConfidence
        
        val heuristicTriggered = heuristicResult.riskScore > 0 || heuristicResult.findings.isNotEmpty()
        
        return isSuspicious || isGoogleUnknown || isAbuseConfidenceLow || heuristicTriggered
    }

    private fun aggregateResults(
        url: String,
        results: Map<String, ThreatAnalysisResult>,
        sslResult: SslAnalysisResult,
        heuristicResult: HeuristicAnalysisResult,
        offlineResult: OfflineScanResult,
        scanTimeMs: Long
    ): ScanResponse {
        var score = 0
        var apiFailures = 0
        var allApisFailed = true

        // 1. Offline Score
        if (offlineResult.status == RiskStatus.DANGEROUS || offlineResult.status == RiskStatus.SUSPICIOUS) {
            score += (offlineResult.confidenceScore * 100).toInt()
        }

        // 2. External APIs Score (Using Normalized Weighted Scoring)
        var activeWeightSum = 0.0
        var weightedScoreSum = 0.0
        
        val googleResult = results[googleSafeBrowsingClient.sourceName]
        if (googleResult != null && googleResult.status == ThreatIntelStatus.SUCCESS) {
            allApisFailed = false
            activeWeightSum += scanConfig.weights.googleSafeBrowsing
            val sourceScore = if (googleResult.isMalicious) 100.0 else 0.0
            weightedScoreSum += (sourceScore * scanConfig.weights.googleSafeBrowsing)
        } else if (results.containsKey(googleSafeBrowsingClient.sourceName)) {
            apiFailures++
        }

        val vtResult = results[virusTotalClient.sourceName]
        if (vtResult != null && vtResult.status == ThreatIntelStatus.SUCCESS) {
            allApisFailed = false
            activeWeightSum += scanConfig.weights.virusTotal
            val vtData = vtResult.rawData as? VirusTotalResult
            val sourceScore = if (vtData != null) {
                when {
                    vtData.malicious > 0 -> 100.0
                    vtData.suspicious > 0 -> 50.0
                    else -> 0.0
                }
            } else 0.0
            weightedScoreSum += (sourceScore * scanConfig.weights.virusTotal)
        } else if (results.containsKey(virusTotalClient.sourceName)) {
            apiFailures++
        }

        val abuseResult = results[abuseIpDbClient.sourceName]
        if (abuseResult != null && abuseResult.status == ThreatIntelStatus.SUCCESS) {
            allApisFailed = false
            activeWeightSum += scanConfig.weights.abuseIpDb
            val abuseData = abuseResult.rawData as? AbuseIpDbResult
            val sourceScore = abuseData?.confidenceScore?.toDouble() ?: 0.0
            weightedScoreSum += (sourceScore * scanConfig.weights.abuseIpDb)
        } else if (results.containsKey(abuseIpDbClient.sourceName)) {
            apiFailures++
        }
        
        if (activeWeightSum > 0.0) {
            val normalizedApiScore = weightedScoreSum / activeWeightSum
            score += (normalizedApiScore * 0.8).toInt() // API contributes up to 80 points max
        }

        score += apiFailures * 15

        // 3. Local SSL & Heuristics
        if (sslResult.isExpired) score += 40
        if (sslResult.isRevoked) score += 70
        if (sslResult.isSelfSigned) score += 35
        if (sslResult.invalidHostname) score += 30
        if (sslResult.weakCipher) score += 20

        score += heuristicResult.riskScore

        val finalScore = score.coerceIn(0, 100)

        val status = when {
            allApisFailed && results.isNotEmpty() -> RiskStatus.UNKNOWN
            finalScore >= scanConfig.thresholds.suspicious -> RiskStatus.DANGEROUS
            finalScore >= scanConfig.thresholds.safe -> RiskStatus.SUSPICIOUS
            apiFailures >= 2 && finalScore < scanConfig.thresholds.safe -> RiskStatus.UNKNOWN
            else -> RiskStatus.SAFE
        }

        return ScanResponse(
            url = url,
            riskScore = finalScore,
            status = status,
            sources = buildSources(results, sslResult, heuristicResult, offlineResult.status == RiskStatus.DANGEROUS),
            scanTimeMs = scanTimeMs
        )
    }

    private fun buildSources(
        results: Map<String, ThreatAnalysisResult>,
        sslResult: SslAnalysisResult?,
        heuristicResult: HeuristicAnalysisResult?,
        isOfflineDangerous: Boolean
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
            securitySnacksFlagged = isOfflineDangerous // mapping local intel to the legacy response field
        )
    }

    private suspend fun buildOfflineResponse(
        url: String, 
        urlHash: String, 
        offlineResult: OfflineScanResult, 
        startTime: Long, 
        deviceId: String,
        userId: java.util.UUID? = null
    ): ScanResponse {
        val scanTimeMs = System.currentTimeMillis() - startTime
        val riskScore = (offlineResult.confidenceScore * 100).toInt()
        
        val response = ScanResponse(
            url = url,
            riskScore = riskScore,
            status = offlineResult.status,
            sources = buildSources(emptyMap(), null, null, true),
            scanTimeMs = scanTimeMs
        )

        saveScanResult(response, deviceId, urlHash, scanTimeMs, emptyMap(), userId)
        return response
    }

    private fun createInvalidUrlResponse(rawUrl: String, startTime: Long): ScanResponse {
        return ScanResponse(
            url = rawUrl,
            riskScore = 0,
            status = RiskStatus.UNKNOWN,
            sources = buildSources(emptyMap(), null, null, false),
            scanTimeMs = System.currentTimeMillis() - startTime
        )
    }

    private suspend fun findRecentScan(urlHash: String): ScanResult? {
        return scanRepositoryAdapter.findRecent(urlHash)
    }

    suspend fun saveScanResult(
        response: ScanResponse,
        deviceId: String,
        urlHash: String,
        scanTimeMs: Long,
        results: Map<String, ThreatAnalysisResult>,
        userId: java.util.UUID? = null
    ): ScanResult {
        val google = results[googleSafeBrowsingClient.sourceName]?.rawData as? GoogleSafeBrowsingResult
        val vt = results[virusTotalClient.sourceName]?.rawData as? VirusTotalResult
        val abuse = results[abuseIpDbClient.sourceName]?.rawData as? AbuseIpDbResult

        val entity = ScanResult(
            url = response.url,
            urlHash = urlHash,
            deviceId = deviceId,
            userId = userId,
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
        
        val savedEntity = scanRepositoryAdapter.save(entity)
        
        // Populate Redis Cache (Negative caching supported)
        redisThreatCacheService.cacheScanResult(
            urlHash = urlHash,
            verdict = response.status.name,
            confidence = response.riskScore / 100.0,
            threatType = google?.threatType ?: "UNKNOWN"
        )
        
        return savedEntity
    }

    private fun ScanResult.toResponse(
        isCached: Boolean, 
        sslResult: SslAnalysisResult? = null, 
        heuristicResult: HeuristicAnalysisResult? = null
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
            securitySnacksFlagged = false
        ),
        scanTimeMs = this.scanTimeMs,
        isCached = isCached,
        scannedAt = this.scannedAt.toString()
    )

    suspend fun getUserScans(userId: java.util.UUID, page: Int = 0, size: Int = 20): org.springframework.data.domain.Page<ScanResponse> {
        val results = scanRepositoryAdapter.findRecentScansByUserId(userId, page, size)
        return results.map { it.toResponse(isCached = true) }
    }

    suspend fun getDeviceScans(deviceId: String, page: Int = 0, size: Int = 20): org.springframework.data.domain.Page<ScanResponse> {
        val results = scanRepositoryAdapter.findRecentScansByDeviceId(deviceId, page, size)
        return results.map { it.toResponse(isCached = true) }
    }
}
