package com.security.scanner.external.integration

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty
import com.security.scanner.config.ThirdPartyConfig
import com.security.scanner.domain.dto.AbuseIpDbResult
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker
import io.github.resilience4j.retry.annotation.Retry
import kotlinx.coroutines.reactor.awaitSingle
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Component
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.WebClientResponseException
import org.springframework.web.reactive.function.client.bodyToMono
import java.net.InetAddress
import java.net.URI
import java.time.Duration

@Component
class AbuseIpDbClient(
    private val config: ThirdPartyConfig,
    private val webClientBuilder: WebClient.Builder
) : ThreatIntelligencePort {

    private val log = LoggerFactory.getLogger(javaClass)

    override val sourceName = "abuseIpDb"
    override val isEnabled get() = config.abuseIpDb.enabled && config.abuseIpDb.apiKey.isNotBlank()

    private val webClient: WebClient by lazy {
        webClientBuilder
            .baseUrl(config.abuseIpDb.baseUrl)
            .defaultHeader("Key", config.abuseIpDb.apiKey)
            .defaultHeader("Accept", "application/json")
            .build()
    }

    @CircuitBreaker(name = "abuseIpDb", fallbackMethod = "fallback")
    @Retry(name = "abuseIpDb")
    override suspend fun analyze(url: String): ThreatAnalysisResult {
        if (!isEnabled) {
            log.warn("AbuseIPDB is disabled or API key is missing")
            return ThreatAnalysisResult(
                sourceName = sourceName,
                riskScore = 0.0,
                isMalicious = false,
                rawData = AbuseIpDbResult(),
                error = "Service disabled",
                status = ThreatIntelStatus.FAILED
            )
        }

        return try {
            // Extract IP or host from URL
            val hostIp = extractIp(url) ?: return ThreatAnalysisResult(
                sourceName = sourceName,
                riskScore = 0.0,
                isMalicious = false,
                rawData = AbuseIpDbResult(),
                error = "Could not extract or resolve IP from URL",
                status = ThreatIntelStatus.FAILED
            )

            val response = webClient.get()
                .uri { uriBuilder ->
                    uriBuilder.path("/api/v2/check")
                        .queryParam("ipAddress", hostIp)
                        .queryParam("maxAgeInDays", 90)
                        .queryParam("verbose", false)
                        .build()
                }
                .retrieve()
                .bodyToMono<AbuseIpDbApiResponse>()
                .timeout(Duration.ofMillis(config.abuseIpDb.timeoutMs))
                .awaitSingle()

            val data = response.data
            val confidenceScore = data?.abuseConfidenceScore ?: 0
            val isMalicious = confidenceScore >= 50

            val rawData = AbuseIpDbResult(
                confidenceScore = confidenceScore,
                countryCode = data?.countryCode,
                domain = data?.domain,
                ipAddress = hostIp,
                isTor = data?.isTor ?: false,
                totalReports = data?.totalReports ?: 0
            )

            ThreatAnalysisResult(
                sourceName = sourceName,
                riskScore = confidenceScore.toDouble(),
                isMalicious = isMalicious,
                rawData = rawData,
                status = ThreatIntelStatus.SUCCESS
            )
        } catch (e: WebClientResponseException) {
            if (e.statusCode.value() == 429) {
                log.warn("AbuseIPDB API rate limited: $url")
                ThreatAnalysisResult(
                    sourceName = sourceName,
                    riskScore = 0.0,
                    isMalicious = false,
                    rawData = null,
                    error = "API rate limited",
                    status = ThreatIntelStatus.RATE_LIMITED
                )
            } else {
                log.error("AbuseIPDB API error: status=${e.statusCode}", e)
                ThreatAnalysisResult(
                    sourceName = sourceName,
                    riskScore = 0.0,
                    isMalicious = false,
                    rawData = null,
                    error = "API error: ${e.statusCode}",
                    status = ThreatIntelStatus.FAILED
                )
            }
        } catch (e: Exception) {
            log.error("AbuseIPDB unexpected error for url=$url", e)
            ThreatAnalysisResult(
                sourceName = sourceName,
                riskScore = 0.0,
                isMalicious = false,
                rawData = null,
                error = e.message,
                status = ThreatIntelStatus.FAILED
            )
        }
    }

    @Suppress("UNUSED_PARAMETER")
    fun fallback(url: String, ex: Exception): ThreatAnalysisResult {
        log.warn("AbuseIPDB circuit breaker open, using fallback for url=$url", ex)
        return ThreatAnalysisResult(
            sourceName = sourceName,
            riskScore = 0.0,
            isMalicious = false,
            rawData = null,
            error = "Service unavailable (circuit open)",
            status = ThreatIntelStatus.TIMEOUT
        )
    }

    private fun extractIp(url: String): String? {
        return try {
            val host = URI(url).host?.removePrefix("www.") ?: return null
            // Check if it's already an IP address
            if (host.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}\$"))) {
                return host
            }
            // Resolve to IP
            InetAddress.getByName(host).hostAddress
        } catch (e: Exception) {
            log.warn("Failed to extract or resolve IP from URL: $url", e)
            null
        }
    }
}

// API Response models
@JsonIgnoreProperties(ignoreUnknown = true)
data class AbuseIpDbApiResponse(
    val data: AbuseIpDbData? = null
)

@JsonIgnoreProperties(ignoreUnknown = true)
data class AbuseIpDbData(
    val ipAddress: String? = null,
    @JsonProperty("isPublic")
    val isPublic: Boolean? = null,
    val ipVersion: Int? = null,
    @JsonProperty("isWhitelisted")
    val isWhitelisted: Boolean? = null,
    @JsonProperty("abuseConfidenceScore")
    val abuseConfidenceScore: Int = 0,
    val countryCode: String? = null,
    val domain: String? = null,
    val totalReports: Int = 0,
    val numDistinctUsers: Int = 0,
    @JsonProperty("lastReportedAt")
    val lastReportedAt: String? = null,
    @JsonProperty("isTor")
    val isTor: Boolean = false
)
