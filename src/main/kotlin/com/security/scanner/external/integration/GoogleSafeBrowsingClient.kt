package com.security.scanner.external.integration

import com.fasterxml.jackson.annotation.JsonProperty
import com.security.scanner.config.ThirdPartyConfig
import com.security.scanner.domain.dto.GoogleSafeBrowsingResult
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker
import io.github.resilience4j.retry.annotation.Retry
import kotlinx.coroutines.reactor.awaitSingle
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Component
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.WebClientResponseException
import org.springframework.web.reactive.function.client.bodyToMono
import java.time.Duration

@Component
class GoogleSafeBrowsingClient(
    private val config: ThirdPartyConfig,
    private val webClientBuilder: WebClient.Builder
) : ThreatIntelligencePort {

    private val log = LoggerFactory.getLogger(javaClass)

    override val sourceName = "googleSafeBrowsing"
    override val isEnabled get() = config.googleSafeBrowsing.enabled && config.googleSafeBrowsing.apiKey.isNotBlank()

    private val webClient: WebClient by lazy {
        webClientBuilder
            .baseUrl(config.googleSafeBrowsing.baseUrl)
            .build()
    }

    @CircuitBreaker(name = "googleSafeBrowsing", fallbackMethod = "fallback")
    @Retry(name = "googleSafeBrowsing")
    override suspend fun analyze(url: String): ThreatAnalysisResult {
        if (!isEnabled) {
            log.warn("Google Safe Browsing is disabled or API key is missing")
            return ThreatAnalysisResult(
                sourceName = sourceName,
                riskScore = 0.0,
                isMalicious = false,
                rawData = GoogleSafeBrowsingResult(flagged = false),
                error = "Service disabled",
                status = ThreatIntelStatus.FAILED
            )
        }

        return try {
            val request = buildRequest(url)
            val response = webClient.post()
                .uri("/v4/threatMatches:find?key=${config.googleSafeBrowsing.apiKey}")
                .bodyValue(request)
                .retrieve()
                .bodyToMono<GoogleSafeBrowsingApiResponse>()
                .timeout(Duration.ofMillis(config.googleSafeBrowsing.timeoutMs))
                .awaitSingle()

            val matches = response.matches ?: emptyList()
            val isMalicious = matches.isNotEmpty()
            val threatType = matches.firstOrNull()?.threatType
            val platformType = matches.firstOrNull()?.platformType

            val rawData = GoogleSafeBrowsingResult(
                flagged = isMalicious,
                threatType = threatType,
                platformType = platformType
            )

            ThreatAnalysisResult(
                sourceName = sourceName,
                riskScore = if (isMalicious) 100.0 else 0.0,
                isMalicious = isMalicious,
                rawData = rawData,
                status = ThreatIntelStatus.SUCCESS
            )
        } catch (e: WebClientResponseException) {
            if (e.statusCode.value() == 429) {
                log.warn("Google Safe Browsing API rate limited: $url")
                ThreatAnalysisResult(
                    sourceName = sourceName,
                    riskScore = 0.0,
                    isMalicious = false,
                    rawData = null,
                    error = "API rate limited",
                    status = ThreatIntelStatus.RATE_LIMITED
                )
            } else {
                log.error("Google Safe Browsing API error: status=${e.statusCode}, body=${e.responseBodyAsString}", e)
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
            log.error("Google Safe Browsing unexpected error for url=$url", e)
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
        log.warn("Google Safe Browsing circuit breaker open, using fallback for url=$url", ex)
        return ThreatAnalysisResult(
            sourceName = sourceName,
            riskScore = 0.0,
            isMalicious = false,
            rawData = null,
            error = "Service unavailable (circuit open)",
            status = ThreatIntelStatus.TIMEOUT
        )
    }

    private fun buildRequest(url: String): GoogleSafeBrowsingRequest = GoogleSafeBrowsingRequest(
        client = ClientInfo(clientId = "mobile-security-scanner", clientVersion = "1.0.0"),
        threatInfo = ThreatInfo(
            threatTypes = listOf(
                "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION", "THREAT_TYPE_UNSPECIFIED"
            ),
            platformTypes = listOf("ANY_PLATFORM"),
            threatEntryTypes = listOf("URL"),
            threatEntries = listOf(ThreatEntry(url = url))
        )
    )
}

// API Request/Response models
data class GoogleSafeBrowsingRequest(
    val client: ClientInfo,
    val threatInfo: ThreatInfo
)

data class ClientInfo(val clientId: String, val clientVersion: String)

data class ThreatInfo(
    val threatTypes: List<String>,
    val platformTypes: List<String>,
    val threatEntryTypes: List<String>,
    val threatEntries: List<ThreatEntry>
)

data class ThreatEntry(val url: String)

data class GoogleSafeBrowsingApiResponse(
    val matches: List<ThreatMatch>? = null
)

data class ThreatMatch(
    val threatType: String?,
    val platformType: String?,
    val threatEntryType: String?,
    val threat: ThreatEntry?
)
