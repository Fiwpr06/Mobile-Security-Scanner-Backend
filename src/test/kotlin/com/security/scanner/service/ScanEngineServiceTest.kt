package com.security.scanner.service

import com.security.scanner.config.ScanConfig
import com.security.scanner.domain.dto.*
import com.security.scanner.domain.model.RiskStatus
import com.security.scanner.external.integration.*
import com.security.scanner.repository.ScanRepositoryAdapter
import com.security.scanner.ssl.SslAnalyzer
import com.security.scanner.heuristic.HeuristicAnalyzer
import io.mockk.*
import io.mockk.impl.annotations.MockK
import kotlinx.coroutines.test.runTest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class ScanEngineServiceTest {

    @MockK private lateinit var googleClient: GoogleSafeBrowsingClient
    @MockK private lateinit var virusTotalClient: VirusTotalClient
    @MockK private lateinit var abuseIpDbClient: AbuseIpDbClient
    @MockK private lateinit var scanRepositoryAdapter: ScanRepositoryAdapter
    @MockK private lateinit var redisThreatCacheService: RedisThreatCacheService
    @MockK private lateinit var sslAnalyzer: SslAnalyzer
    @MockK private lateinit var heuristicAnalyzer: HeuristicAnalyzer
    @MockK private lateinit var offlineThreatIntelService: OfflineThreatIntelService
    @MockK private lateinit var canonicalUrlService: CanonicalUrlService

    private lateinit var scanConfig: ScanConfig
    private lateinit var scanEngineService: ScanEngineService

    @BeforeEach
    fun setUp() {
        MockKAnnotations.init(this)
        scanConfig = ScanConfig().apply {
            weights.googleSafeBrowsing = 0.5
            weights.virusTotal = 0.3
            weights.abuseIpDb = 0.2
            thresholds.safe = 30
            thresholds.suspicious = 60
            parallelEnabled = false
            fastFailOnDangerous = true
        }

        every { googleClient.sourceName } returns "googleSafeBrowsing"
        every { googleClient.isEnabled } returns true
        every { virusTotalClient.sourceName } returns "virusTotal"
        every { virusTotalClient.isEnabled } returns true
        every { abuseIpDbClient.sourceName } returns "abuseIpDb"
        every { abuseIpDbClient.isEnabled } returns true

        // Default: no cached scan, no offline threat
        coEvery { scanRepositoryAdapter.findRecent(any()) } returns null
        coEvery { scanRepositoryAdapter.save(any()) } answers { firstArg() }
        coEvery { redisThreatCacheService.getCachedUrlThreat(any()) } returns null
        coEvery { redisThreatCacheService.cacheScanResult(any(), any(), any(), any()) } just Runs

        // Default canonicalization
        every { canonicalUrlService.canonicalize(any()) } answers {
            val raw = firstArg<String>()
            CanonicalUrlData(
                normalizedDomain = "example.com",
                normalizedPath = "/",
                urlHash = "hash_" + raw.hashCode(),
                fullCanonicalUrl = raw
            )
        }

        // Default offline threat evaluation
        every { offlineThreatIntelService.evaluateUrl(any()) } returns OfflineScanResult(
            status = RiskStatus.SAFE,
            threatType = null,
            confidenceScore = 0.0,
            fastReturn = false,
            skipExternalApis = false
        )

        // Default local analyzers
        coEvery { sslAnalyzer.analyze(any()) } returns SslAnalysisResult(isValid = true)
        coEvery { heuristicAnalyzer.analyze(any()) } returns HeuristicAnalysisResult(riskScore = 0)

        scanEngineService = ScanEngineService(
            googleClient, virusTotalClient, abuseIpDbClient,
            scanRepositoryAdapter, redisThreatCacheService, scanConfig,
            sslAnalyzer, heuristicAnalyzer, offlineThreatIntelService, canonicalUrlService
        )
    }

    @Test
    fun `should return SAFE when all sources report clean and skip VirusTotal`() = runTest {
        // Given
        coEvery { googleClient.analyze(any()) } returns ThreatAnalysisResult(
            sourceName = "googleSafeBrowsing", riskScore = 0.0, isMalicious = false,
            rawData = GoogleSafeBrowsingResult(flagged = false), status = ThreatIntelStatus.SUCCESS
        )
        // Set abuseIpdb confidence high enough (>= 15) to NOT trigger VirusTotal
        coEvery { abuseIpDbClient.analyze(any()) } returns ThreatAnalysisResult(
            sourceName = "abuseIpDb", riskScore = 20.0, isMalicious = false,
            rawData = AbuseIpDbResult(confidenceScore = 20), status = ThreatIntelStatus.SUCCESS
        )

        // When
        val result = scanEngineService.scanUrl("https://google.com", "device-123")

        // Then
        assertThat(result.status).isEqualTo(RiskStatus.SAFE)
        assertThat(result.riskScore).isLessThan(30)
        
        // Verify sequential scanning: Google and AbuseIPDB are called, but VirusTotal is skipped
        coVerify(exactly = 1) { googleClient.analyze(any()) }
        coVerify(exactly = 1) { abuseIpDbClient.analyze(any()) }
        coVerify(exactly = 0) { virusTotalClient.analyze(any()) }
    }

    @Test
    fun `should fast-return immediately when Google Safe Browsing flags URL`() = runTest {
        // Given
        coEvery { googleClient.analyze(any()) } returns ThreatAnalysisResult(
            sourceName = "googleSafeBrowsing", riskScore = 100.0, isMalicious = true,
            rawData = GoogleSafeBrowsingResult(flagged = true, threatType = "MALWARE"), status = ThreatIntelStatus.SUCCESS
        )

        // When
        val result = scanEngineService.scanUrl("https://malicious-site.com", "device-123")

        // Then
        assertThat(result.status).isEqualTo(RiskStatus.DANGEROUS)
        
        // Verify Fast-Return: Google is called, but AbuseIPDB and VirusTotal are NEVER called
        coVerify(exactly = 1) { googleClient.analyze(any()) }
        coVerify(exactly = 0) { abuseIpDbClient.analyze(any()) }
        coVerify(exactly = 0) { virusTotalClient.analyze(any()) }
    }

    @Test
    fun `should trigger VirusTotal when intermediate score is suspicious`() = runTest {
        // Given - Google clean, but AbuseIPDB reports very high score resulting in SUSPICIOUS risk
        coEvery { googleClient.analyze(any()) } returns ThreatAnalysisResult(
            sourceName = "googleSafeBrowsing", riskScore = 0.0, isMalicious = false,
            rawData = GoogleSafeBrowsingResult(flagged = false), status = ThreatIntelStatus.SUCCESS
        )
        // With high AbuseIPDB score, the intermediate score will trigger the suspicious threshold
        coEvery { abuseIpDbClient.analyze(any()) } returns ThreatAnalysisResult(
            sourceName = "abuseIpDb", riskScore = 95.0, isMalicious = true,
            rawData = AbuseIpDbResult(confidenceScore = 95), status = ThreatIntelStatus.SUCCESS
        )
        // Mock a revoked certificate to add 70 points to the intermediate score, triggering the VirusTotal Deep Inspection
        coEvery { sslAnalyzer.analyze(any()) } returns SslAnalysisResult(isValid = false, isRevoked = true)
        
        coEvery { virusTotalClient.analyze(any()) } returns ThreatAnalysisResult(
            sourceName = "virusTotal", riskScore = 10.0, isMalicious = false,
            rawData = VirusTotalResult(malicious = 0, totalEngines = 70), status = ThreatIntelStatus.SUCCESS
        )

        // When
        scanEngineService.scanUrl("https://suspicious-site.com", "device-123")

        // Then
        // Verify VirusTotal is triggered because intermediate risk was high
        coVerify(exactly = 1) { googleClient.analyze(any()) }
        coVerify(exactly = 1) { abuseIpDbClient.analyze(any()) }
        coVerify(exactly = 1) { virusTotalClient.analyze(any()) }
    }

    @Test
    fun `should trigger VirusTotal when Google Safe Browsing is UNKNOWN`() = runTest {
        // Given
        coEvery { googleClient.analyze(any()) } returns ThreatAnalysisResult(
            sourceName = "googleSafeBrowsing", riskScore = 0.0, isMalicious = false,
            rawData = null, status = ThreatIntelStatus.UNKNOWN
        )
        coEvery { abuseIpDbClient.analyze(any()) } returns ThreatAnalysisResult(
            sourceName = "abuseIpDb", riskScore = 20.0, isMalicious = false,
            rawData = AbuseIpDbResult(confidenceScore = 20), status = ThreatIntelStatus.SUCCESS
        )
        coEvery { virusTotalClient.analyze(any()) } returns ThreatAnalysisResult(
            sourceName = "virusTotal", riskScore = 0.0, isMalicious = false,
            rawData = VirusTotalResult(malicious = 0), status = ThreatIntelStatus.SUCCESS
        )

        // When
        scanEngineService.scanUrl("https://unknown-google.com", "device-123")

        // Then
        // Should trigger VirusTotal because Google is UNKNOWN
        coVerify(exactly = 1) { virusTotalClient.analyze(any()) }
    }

    @Test
    fun `should trigger VirusTotal when AbuseIPDB confidence score is low`() = runTest {
        // Given
        coEvery { googleClient.analyze(any()) } returns ThreatAnalysisResult(
            sourceName = "googleSafeBrowsing", riskScore = 0.0, isMalicious = false,
            rawData = GoogleSafeBrowsingResult(flagged = false), status = ThreatIntelStatus.SUCCESS
        )
        coEvery { abuseIpDbClient.analyze(any()) } returns ThreatAnalysisResult(
            sourceName = "abuseIpDb", riskScore = 5.0, isMalicious = false,
            rawData = AbuseIpDbResult(confidenceScore = 5), status = ThreatIntelStatus.SUCCESS
        )
        coEvery { virusTotalClient.analyze(any()) } returns ThreatAnalysisResult(
            sourceName = "virusTotal", riskScore = 0.0, isMalicious = false,
            rawData = VirusTotalResult(malicious = 0), status = ThreatIntelStatus.SUCCESS
        )

        // When
        scanEngineService.scanUrl("https://low-abuse-confidence.com", "device-123")

        // Then
        // Should trigger VirusTotal because AbuseIPDB confidence (5) < MIN_CONFIDENCE (15)
        coVerify(exactly = 1) { virusTotalClient.analyze(any()) }
    }

    @Test
    fun `should trigger VirusTotal when heuristics are triggered`() = runTest {
        // Given
        coEvery { googleClient.analyze(any()) } returns ThreatAnalysisResult(
            sourceName = "googleSafeBrowsing", riskScore = 0.0, isMalicious = false,
            rawData = GoogleSafeBrowsingResult(flagged = false), status = ThreatIntelStatus.SUCCESS
        )
        coEvery { abuseIpDbClient.analyze(any()) } returns ThreatAnalysisResult(
            sourceName = "abuseIpDb", riskScore = 20.0, isMalicious = false,
            rawData = AbuseIpDbResult(confidenceScore = 20), status = ThreatIntelStatus.SUCCESS
        )
        // Heuristics triggered!
        coEvery { heuristicAnalyzer.analyze(any()) } returns HeuristicAnalysisResult(
            riskScore = 40, findings = listOf("Suspicious TLD")
        )
        coEvery { virusTotalClient.analyze(any()) } returns ThreatAnalysisResult(
            sourceName = "virusTotal", riskScore = 0.0, isMalicious = false,
            rawData = VirusTotalResult(malicious = 0), status = ThreatIntelStatus.SUCCESS
        )

        // When
        scanEngineService.scanUrl("https://heuristic-site.xyz", "device-123")

        // Then
        // Should trigger VirusTotal because heuristics were triggered
        coVerify(exactly = 1) { virusTotalClient.analyze(any()) }
    }

    @Test
    fun `should handle service failures gracefully and fallback to UNKNOWN`() = runTest {
        // Given - all services fail with TIMEOUT / FAILED
        coEvery { googleClient.analyze(any()) } returns ThreatAnalysisResult(
            sourceName = "googleSafeBrowsing", riskScore = 0.0, isMalicious = false,
            rawData = null, error = "Circuit open", status = ThreatIntelStatus.TIMEOUT
        )
        coEvery { abuseIpDbClient.analyze(any()) } returns ThreatAnalysisResult(
            sourceName = "abuseIpDb", riskScore = 0.0, isMalicious = false,
            rawData = null, error = "API key invalid", status = ThreatIntelStatus.FAILED
        )
        coEvery { virusTotalClient.analyze(any()) } returns ThreatAnalysisResult(
            sourceName = "virusTotal", riskScore = 0.0, isMalicious = false,
            rawData = null, error = "Timeout", status = ThreatIntelStatus.TIMEOUT
        )

        // When
        val result = scanEngineService.scanUrl("https://failure-site.com", "device-123")

        // Then
        assertThat(result).isNotNull
        assertThat(result.status).isEqualTo(RiskStatus.UNKNOWN)
    }
}
