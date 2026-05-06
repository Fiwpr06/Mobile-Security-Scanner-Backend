package com.security.scanner.external.integration

import com.security.scanner.config.SecuritySnacksConfig
import kotlinx.coroutines.reactor.awaitSingleOrNull
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Component
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.reactive.function.client.bodyToMono
import java.time.Duration
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnoreProperties

@JsonIgnoreProperties(ignoreUnknown = true)
data class GitHubTreeResponse(
    val tree: List<GitHubTreeEntry> = emptyList()
)

@JsonIgnoreProperties(ignoreUnknown = true)
data class GitHubTreeEntry(
    val path: String,
    val type: String
)

@Component
class SecuritySnacksClient(
    private val webClientBuilder: WebClient.Builder,
    private val config: SecuritySnacksConfig
) {
    private val log = LoggerFactory.getLogger(javaClass)
    private val webClient = webClientBuilder.build()

    suspend fun fetchFeedData(url: String): String? {
        if (!config.enabled) return null
        
        return try {
            log.info("Fetching SecuritySnacks feed from $url")
            webClient.get()
                .uri(url)
                .retrieve()
                .bodyToMono<String>()
                .timeout(Duration.ofMillis(config.connectionTimeout))
                .awaitSingleOrNull()
        } catch (e: Exception) {
            log.error("Failed to fetch SecuritySnacks feed at $url: ${e.message}")
            null
        }
    }

    suspend fun discoverCsvFeeds(): List<String> {
        val treeUrl = "https://api.github.com/repos/DomainTools/SecuritySnacks/git/trees/main?recursive=1"
        return try {
            log.info("Discovering all CSV feeds from GitHub API...")
            val response = webClient.get()
                .uri(treeUrl)
                .header("User-Agent", "SecurityScanner-Backend")
                .retrieve()
                .bodyToMono<GitHubTreeResponse>()
                .awaitSingleOrNull()

            response?.tree
                ?.filter { it.type == "blob" && it.path.endsWith(".csv") }
                ?.map { "https://raw.githubusercontent.com/DomainTools/SecuritySnacks/main/${it.path}" }
                ?: emptyList()
        } catch (e: Exception) {
            log.error("Failed to discover CSV feeds: ${e.message}")
            emptyList()
        }
    }
}
