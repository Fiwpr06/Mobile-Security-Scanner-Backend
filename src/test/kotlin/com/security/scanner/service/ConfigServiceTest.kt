package com.security.scanner.service

import com.security.scanner.config.ScanConfig
import com.security.scanner.domain.dto.AppConfigResponse
import com.security.scanner.domain.dto.ScoringThresholds
import com.security.scanner.domain.dto.ScoringWeights
import com.security.scanner.domain.model.DangerousDomain
import com.security.scanner.repository.DangerousDomainRepository
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.kotlin.*
import org.springframework.data.domain.PageImpl
import org.springframework.data.domain.Pageable

class ConfigServiceTest {

    private lateinit var scanConfig: ScanConfig
    private lateinit var dangerousDomainRepository: DangerousDomainRepository
    private lateinit var configService: ConfigService

    @BeforeEach
    fun setUp() {
        scanConfig = ScanConfig().apply {
            weights.googleSafeBrowsing = 0.5
            weights.virusTotal = 0.3
            weights.abuseIpDb = 0.2
            thresholds.safe = 30
            thresholds.suspicious = 60
            parallelEnabled = true
            fastFailOnDangerous = true
        }

        dangerousDomainRepository = mock()

        configService = ConfigService(
            scanConfig = scanConfig,
            dangerousDomainRepository = dangerousDomainRepository,
            minimumAppVersion = "1.0.0",
            maintenance = false,
            maintenanceMessage = ""
        )
    }

    // ─── Happy Path ───────────────────────────────────────────────────────────

    @Test
    fun `should return app config with correct weights and thresholds`() {
        whenever(dangerousDomainRepository.findAll(any<Pageable>())).thenReturn(PageImpl(emptyList()))

        val config = configService.getAppConfig()

        assertThat(config.weights.google).isEqualTo(0.5)
        assertThat(config.weights.virusTotal).isEqualTo(0.3)
        assertThat(config.weights.abuseIpDb).isEqualTo(0.2)
        assertThat(config.thresholds.safe).isEqualTo(30)
        assertThat(config.thresholds.suspicious).isEqualTo(60)
        assertThat(config.minimumAppVersion).isEqualTo("1.0.0")
        assertThat(config.maintenance).isFalse()
    }

    @Test
    fun `should include dangerous domains in offline threat list`() {
        val domains = listOf(
            makeDomain("evil.com"),
            makeDomain("phishing-site.net")
        )
        whenever(dangerousDomainRepository.findAll(any<Pageable>())).thenReturn(PageImpl(domains))

        val config = configService.getAppConfig()

        assertThat(config.offlineThreatList).containsExactlyInAnyOrder("evil.com", "phishing-site.net")
    }

    @Test
    fun `should include feature flags from scan config`() {
        whenever(dangerousDomainRepository.findAll(any<Pageable>())).thenReturn(PageImpl(emptyList()))

        val config = configService.getAppConfig()

        assertThat(config.featureFlags["parallelScan"]).isTrue()
        assertThat(config.featureFlags["fastFailOnDangerous"]).isTrue()
        assertThat(config.featureFlags["cachingEnabled"]).isTrue()
        assertThat(config.featureFlags["reportingEnabled"]).isTrue()
    }

    // ─── Maintenance Mode ─────────────────────────────────────────────────────

    @Test
    fun `should return maintenance = true when configured`() {
        val maintenanceConfigService = ConfigService(
            scanConfig = scanConfig,
            dangerousDomainRepository = dangerousDomainRepository,
            minimumAppVersion = "1.0.0",
            maintenance = true,
            maintenanceMessage = "Scheduled maintenance"
        )
        whenever(dangerousDomainRepository.findAll(any<Pageable>())).thenReturn(PageImpl(emptyList()))

        val config = maintenanceConfigService.getAppConfig()

        assertThat(config.maintenance).isTrue()
        assertThat(config.maintenanceMessage).isEqualTo("Scheduled maintenance")
    }

    @Test
    fun `should return null maintenance message when message is blank`() {
        val noMsgConfigService = ConfigService(
            scanConfig = scanConfig,
            dangerousDomainRepository = dangerousDomainRepository,
            minimumAppVersion = "1.0.0",
            maintenance = false,
            maintenanceMessage = "   " // blank string
        )
        whenever(dangerousDomainRepository.findAll(any<Pageable>())).thenReturn(PageImpl(emptyList()))

        val config = noMsgConfigService.getAppConfig()

        assertThat(config.maintenanceMessage).isNull()
    }

    // ─── BUG FIX: Fail Gracefully When DB Is Unavailable ────────────────────

    @Test
    fun `should return empty offline threat list when DB throws exception (public endpoint must not 500)`() {
        // Simulates a DB failure while the server is still starting or DB is temporarily unavailable
        whenever(dangerousDomainRepository.findAll(any<Pageable>()))
            .thenThrow(RuntimeException("Connection refused"))

        // Must NOT throw — public endpoint should always respond
        val config = configService.getAppConfig()

        assertThat(config).isNotNull
        assertThat(config.offlineThreatList).isEmpty()
        // Core config should still be populated correctly
        assertThat(config.weights.google).isEqualTo(0.5)
        assertThat(config.maintenance).isFalse()
    }

    // ─── Timeout calculated correctly ────────────────────────────────────────

    @Test
    fun `should return maximum timeout from all configured clients`() {
        whenever(dangerousDomainRepository.findAll(any<Pageable>())).thenReturn(PageImpl(emptyList()))

        val config = configService.getAppConfig()

        // maxOf(5000, 10000, 5000) = 10000
        assertThat(config.timeoutMs).isEqualTo(10000L)
    }

    // ─── Helper ───────────────────────────────────────────────────────────────

    private fun makeDomain(domain: String): DangerousDomain =
        DangerousDomain(domain = domain)
}
