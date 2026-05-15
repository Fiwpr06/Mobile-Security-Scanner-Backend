package com.security.scanner.service

import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import java.net.IDN
import java.net.URI
import java.net.URLDecoder
import java.security.MessageDigest

data class CanonicalUrlData(
    val normalizedDomain: String,
    val normalizedPath: String,
    val urlHash: String,
    val fullCanonicalUrl: String
)

@Service
class CanonicalUrlService {
    private val log = LoggerFactory.getLogger(javaClass)
    private val trackingParams = setOf(
        "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
        "fbclid", "gclid", "msclkid", "mc_cid", "mc_eid"
    )

    fun canonicalize(rawUrl: String): CanonicalUrlData? {
        try {
            var url = rawUrl.trim()
            
            // Repeated slash cleanup after scheme
            url = url.replace(Regex("(?<!:)/{2,}"), "/")

            // Safe URL decoding (decode once to handle simple percent encoding, but avoid double-decode issues if malformed)
            try {
                url = URLDecoder.decode(url, "UTF-8")
            } catch (e: Exception) {
                // Ignore decoding errors
            }

            // Ensure protocol exists for URI parsing
            if (!url.startsWith("http://") && !url.startsWith("https://")) {
                url = "http://$url"
            }

            val uri = URI(url)
            
            var host = uri.host ?: return null
            
            // Lowercase domain
            host = host.lowercase()
            
            // Trailing dot removal
            if (host.endsWith(".")) {
                host = host.dropLast(1)
            }
            
            // Punycode normalization
            host = IDN.toASCII(host)

            // Port stripping
            var portStr = ""
            if (uri.port != -1) {
                if (!(uri.scheme == "http" && uri.port == 80) && !(uri.scheme == "https" && uri.port == 443)) {
                    portStr = ":${uri.port}"
                }
            }

            // Path normalization
            var path = uri.path ?: ""
            if (path.isEmpty()) path = "/"
            
            // Trailing slash removal (unless it's just "/")
            if (path.length > 1 && path.endsWith("/")) {
                path = path.dropLast(1)
            }

            // Query parameter filtering
            val query = uri.query
            var canonicalQuery = ""
            if (!query.isNullOrEmpty()) {
                val params = query.split("&").mapNotNull {
                    val parts = it.split("=", limit = 2)
                    if (parts.isNotEmpty()) {
                        val key = parts[0].lowercase()
                        if (trackingParams.contains(key)) null else it
                    } else null
                }.sorted() // sort to ensure canonical order
                
                if (params.isNotEmpty()) {
                    canonicalQuery = "?" + params.joinToString("&")
                }
            }

            val canonicalUrl = "${uri.scheme}://$host$portStr$path$canonicalQuery"
            val hash = hashUrl(canonicalUrl)

            return CanonicalUrlData(
                normalizedDomain = host,
                normalizedPath = "$path$canonicalQuery",
                urlHash = hash,
                fullCanonicalUrl = canonicalUrl
            )
        } catch (e: Exception) {
            log.warn("Failed to canonicalize URL: $rawUrl", e.message)
            return null
        }
    }

    private fun hashUrl(url: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hashBytes = digest.digest(url.toByteArray())
        return hashBytes.joinToString("") { "%02x".format(it) }
    }
}
