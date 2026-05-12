package com.security.scanner.service

import com.security.scanner.config.ScanConfig
import com.security.scanner.domain.dto.*
import com.security.scanner.domain.model.RiskStatus
import com.security.scanner.external.integration.*
import com.security.scanner.repository.MaliciousUrlRepository
import com.security.scanner.repository.ScanResultRepository
import io.mockk.*
import io.mockk.impl.annotations.MockK
import kotlinx.coroutines.test.runTest
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.Optional

class ScanEngineServiceTest {

    @MockK private lateinit var googleClient: GoogleSafeBrowsingClient
    @MockK private lateinit var virusTotalClient: VirusTotalClient
    @MockK private lateinit var abuseIpDbClient: AbuseIpDbClient
    @MockK private lateinit var scanResultRepository: ScanResultRepository
    @MockK private lateinit var maliciousUrlRepository: MaliciousUrlRepository

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
            parallelEnabled = true
            fastFailOnDangerous = false // simpler for tests
        }

        every { googleClient.sourceName } returns "googleSafeBrowsing"
        every { googleClient.isEnabled } returns true
        every { virusTotalClient.sourceName } returns "virusTotal"
        every { virusTotalClient.isEnabled } returns true
        every { abuseIpDbClient.sourceName } returns "abuseIpDb"
        every { abuseIpDbClient.isEnabled } returns true

        // Default: no cached scan
        every { scanResultRepository.findTopByUrlHashOrderByScannedAtDesc(any()) } returns Optional.empty()
        every { scanResultRepository.save(any()) } answers { firstArg() }
        every { maliciousUrlRepository.existsByUrlHash(any()) } returns false
        every { maliciousUrlRepository.save(any()) } answers { firstArg() }

        scanEngineService = ScanEngineService(
            googleClient, virusTotalClient, abuseIpDbClient,
            scanResultRepository, maliciousUrlRepository, scanConfig
        )
    }

    @Test
    fun `should return SAFE when all sources report clean`() = runTest {
        // Given
        coEvery { googleClient.analyze(any()) } returns ThreatAnalysisResult(
            sourceName = "googleSafeBrowsing", riskScore = 0.0, isMalicious = false,
            rawData = GoogleSafeBrowsingResult(flagged = false)
        )
        coEvery { virusTotalClient.analyze(any()) } returns ThreatAnalysisResult(
            sourceName = "virusTotal", riskScore = 0.0, isMalicious = false,
            rawData = VirusTotalResult(malicious = 0, totalEngines = 70)
        )
        coEvery { abuseIpDbClient.analyze(any()) } returns ThreatAnalysisResult(
            sourceName = "abuseIpDb", riskScore = 5.0, isMalicious = false,
            rawData = AbuseIpDbResult(confidenceScore = 5)
        )

        // When
        val result = scanEngineService.scanUrl("https://google.com", "device-123")

        // Then
        assertThat(result.status).isEqualTo(RiskStatus.SAFE)
        assertThat(result.riskScore).isLessThan(30)
    }

    @Test
    fun `should return DANGEROUS when Google Safe Browsing flags URL`() = runTest {
        // Given
        coEvery { googleClient.analyze(any()) } returns ThreatAnalysisResult(
            sourceName = "googleSafeBrowsing", riskScore = 100.0, isMalicious = true,
            rawData = GoogleSafeBrowsingResult(flagged = true, threatType = "MALWARE")
        )
        coEvery { virusTotalClient.analyze(any()) } returns ThreatAnalysisResult(
            sourceName = "virusTotal", riskScore = 80.0, isMalicious = true,
            rawData = VirusTotalResult(malicious = 45, totalEngines = 70)
        )
        coEvery { abuseIpDbClient.analyze(any()) } returns ThreatAnalysisResult(
            sourceName = "abuseIpDb", riskScore = 90.0, isMalicious = true,
            rawData = AbuseIpDbResult(confidenceScore = 90)
        )

        // When
        val result = scanEngineService.scanUrl("https://malicious-site.com", "device-123")

        // Then
        assertThat(result.status).isEqualTo(RiskStatus.DANGEROUS)
        assertThat(result.riskScore).isGreaterThanOrEqualTo(60)
        assertThat(result.sources.googleSafeBrowsing?.flagged).isTrue()
    }

    @Test
    fun `should return SUSPICIOUS for medium risk`() = runTest {
        // Given - moderate VirusTotal detections
        coEvery { googleClient.analyze(any()) } returns ThreatAnalysisResult(
            sourceName = "googleSafeBrowsing", riskScore = 0.0, isMalicious = false,
            rawData = GoogleSafeBrowsingResult(flagged = false)
        )
        coEvery { virusTotalClient.analyze(any()) } returns ThreatAnalysisResult(
            sourceName = "virusTotal", riskScore = 60.0, isMalicious = true,
            rawData = VirusTotalResult(malicious = 5, suspicious = 3, totalEngines = 70)
        )
        coEvery { abuseIpDbClient.analyze(any()) } returns ThreatAnalysisResult(
            sourceName = "abuseIpDb", riskScore = 40.0, isMalicious = false,
            rawData = AbuseIpDbResult(confidenceScore = 40)
        )

        // When
        val result = scanEngineService.scanUrl("https://suspicious-site.com", "device-123")

        // Then
        assertThat(result.status).isEqualTo(RiskStatus.SUSPICIOUS)
    }

    @Test
    fun `should handle service failures gracefully`() = runTest {
        // Given - all services fail
        coEvery { googleClient.analyze(any()) } returns ThreatAnalysisResult(
            sourceName = "googleSafeBrowsing", riskScore = 0.0, isMalicious = false,
            rawData = null, error = "Circuit open", success = false
        )
        coEvery { virusTotalClient.analyze(any()) } returns ThreatAnalysisResult(
            sourceName = "virusTotal", riskScore = 0.0, isMalicious = false,
            rawData = null, error = "Timeout", success = false
        )
        coEvery { abuseIpDbClient.analyze(any()) } returns ThreatAnalysisResult(
            sourceName = "abuseIpDb", riskScore = 0.0, isMalicious = false,
            rawData = null, error = "API key invalid", success = false
        )

        // When - should not throw
        val result = scanEngineService.scanUrl("https://example.com", "device-123")

        // Then
        assertThat(result).isNotNull
        assertThat(result.status).isEqualTo(RiskStatus.SAFE)
    }

    @Test
    fun `weighted score should respect configured weights`() = runTest {
        // Google (50% weight) score=100, others=0
        // Expected: 100*0.5 / (0.5+0.3+0.2) = 50.0
        coEvery { googleClient.analyze(any()) } returns ThreatAnalysisResult(
            sourceName = "googleSafeBrowsing", riskScore = 100.0, isMalicious = true,
            rawData = GoogleSafeBrowsingResult(flagged = true)
        )
        coEvery { virusTotalClient.analyze(any()) } returns ThreatAnalysisResult(
            sourceName = "virusTotal", riskScore = 0.0, isMalicious = false,
            rawData = VirusTotalResult()
        )
        coEvery { abuseIpDbClient.analyze(any()) } returns ThreatAnalysisResult(
            sourceName = "abuseIpDb", riskScore = 0.0, isMalicious = false,
            rawData = AbuseIpDbResult()
        )
        every { maliciousUrlRepository.save(any()) } answers { firstArg() }

        val result = scanEngineService.scanUrl("https://test.com", "device-test")
        assertThat(result.riskScore).isEqualTo(50) // 100*0.5 = 50
        assertThat(result.status).isEqualTo(RiskStatus.SUSPICIOUS) // 50 is in SUSPICIOUS range (30-60)
    }
}
