package com.security.scanner.external.integration

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty
import com.security.scanner.config.ThirdPartyConfig
import com.security.scanner.domain.dto.VirusTotalResult
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker
import io.github.resilience4j.retry.annotation.Retry
import kotlinx.coroutines.reactor.awaitSingle
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Component
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.WebClientResponseException
import org.springframework.web.reactive.function.client.bodyToMono
import java.time.Duration
import java.util.Base64

@Component
class VirusTotalClient(
    private val config: ThirdPartyConfig,
    private val webClientBuilder: WebClient.Builder
) : ThreatIntelligencePort {

    private val log = LoggerFactory.getLogger(javaClass)

    override val sourceName = "virusTotal"
    override val isEnabled get() = config.virusTotal.enabled && config.virusTotal.apiKey.isNotBlank()

    private val webClient: WebClient by lazy {
        webClientBuilder
            .baseUrl(config.virusTotal.baseUrl)
            .defaultHeader("x-apikey", config.virusTotal.apiKey)
            .defaultHeader("Accept", "application/json")
            .build()
    }

    @CircuitBreaker(name = "virusTotal", fallbackMethod = "fallback")
    @Retry(name = "virusTotal")
    override suspend fun analyze(url: String): ThreatAnalysisResult {
        if (!isEnabled) {
            log.warn("VirusTotal is disabled or API key is missing")
            return ThreatAnalysisResult(
                sourceName = sourceName,
                riskScore = 0.0,
                isMalicious = false,
                rawData = VirusTotalResult(),
                error = "Service disabled",
                success = false
            )
        }

        return try {
            // VirusTotal uses base64url-encoded URL as the identifier
            val urlId = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(url.toByteArray())

            val response = webClient.get()
                .uri("/api/v3/urls/$urlId")
                .retrieve()
                .bodyToMono<VirusTotalUrlResponse>()
                .timeout(Duration.ofMillis(config.virusTotal.timeoutMs))
                .awaitSingle()

            val stats = response.data?.attributes?.lastAnalysisStats
            val malicious = stats?.malicious ?: 0
            val suspicious = stats?.suspicious ?: 0
            val harmless = stats?.harmless ?: 0
            val undetected = stats?.undetected ?: 0
            val total = malicious + suspicious + harmless + undetected

            // Calculate risk score based on detection ratio
            val detectionRatio = if (total > 0) ((malicious + suspicious * 0.5) / total) else 0.0
            val riskScore = (detectionRatio * 100).coerceIn(0.0, 100.0)

            val rawData = VirusTotalResult(
                malicious = malicious,
                suspicious = suspicious,
                harmless = harmless,
                undetected = undetected,
                totalEngines = total,
                permalink = response.data?.links?.self
            )

            ThreatAnalysisResult(
                sourceName = sourceName,
                riskScore = riskScore,
                isMalicious = malicious > 0,
                rawData = rawData
            )
        } catch (e: WebClientResponseException) {
            if (e.statusCode.value() == 404) {
                // URL not found in VirusTotal - not necessarily safe
                log.info("URL not found in VirusTotal database: $url")
                ThreatAnalysisResult(
                    sourceName = sourceName,
                    riskScore = 0.0,
                    isMalicious = false,
                    rawData = VirusTotalResult(),
                    error = null,
                    success = true
                )
            } else {
                log.error("VirusTotal API error: status=${e.statusCode}", e)
                ThreatAnalysisResult(
                    sourceName = sourceName,
                    riskScore = 0.0,
                    isMalicious = false,
                    rawData = null,
                    error = "API error: ${e.statusCode}",
                    success = false
                )
            }
        } catch (e: Exception) {
            log.error("VirusTotal unexpected error for url=$url", e)
            ThreatAnalysisResult(
                sourceName = sourceName,
                riskScore = 0.0,
                isMalicious = false,
                rawData = null,
                error = e.message,
                success = false
            )
        }
    }

    @Suppress("UNUSED_PARAMETER")
    fun fallback(url: String, ex: Exception): ThreatAnalysisResult {
        log.warn("VirusTotal circuit breaker open, using fallback for url=$url", ex)
        return ThreatAnalysisResult(
            sourceName = sourceName,
            riskScore = 0.0,
            isMalicious = false,
            rawData = null,
            error = "Service unavailable (circuit open)",
            success = false
        )
    }
}

// API Response models
@JsonIgnoreProperties(ignoreUnknown = true)
data class VirusTotalUrlResponse(
    val data: VirusTotalData? = null
)

@JsonIgnoreProperties(ignoreUnknown = true)
data class VirusTotalData(
    val id: String? = null,
    val type: String? = null,
    val attributes: VirusTotalAttributes? = null,
    val links: VirusTotalLinks? = null
)

@JsonIgnoreProperties(ignoreUnknown = true)
data class VirusTotalAttributes(
    @JsonProperty("last_analysis_stats")
    val lastAnalysisStats: AnalysisStats? = null,
    @JsonProperty("last_final_url")
    val lastFinalUrl: String? = null,
    val reputation: Int? = null
)

@JsonIgnoreProperties(ignoreUnknown = true)
data class AnalysisStats(
    val malicious: Int = 0,
    val suspicious: Int = 0,
    val harmless: Int = 0,
    val undetected: Int = 0
)

@JsonIgnoreProperties(ignoreUnknown = true)
data class VirusTotalLinks(
    val self: String? = null
)
