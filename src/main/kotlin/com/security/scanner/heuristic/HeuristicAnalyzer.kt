package com.security.scanner.heuristic

import com.security.scanner.domain.dto.HeuristicAnalysisResult
import org.springframework.stereotype.Component
import java.net.URI
import java.net.URLDecoder

@Component
class HeuristicAnalyzer {

    private val suspiciousKeywords = listOf("login", "verify", "update", "secure", "account", "banking", "wallet", "support", "auth")
    private val suspiciousTlds = listOf(".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw", ".cc")

    fun analyze(urlStr: String): HeuristicAnalysisResult {
        var score = 0
        val findings = mutableListOf<String>()

        try {
            val uri = URI(urlStr)
            val host = uri.host?.lowercase() ?: ""
            val path = uri.path?.lowercase() ?: ""
            val query = uri.query?.lowercase() ?: ""

            // 1. IP-based URL
            if (host.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}\$"))) {
                score += 30
                findings.add("IP-based URL")
            }

            // 2. Punycode
            if (host.contains("xn--")) {
                score += 40
                findings.add("Punycode domain (possible spoofing)")
            }

            // 3. Excessive length
            if (urlStr.length > 100) {
                score += 15
                findings.add("Excessive URL length")
            }

            // 4. Suspicious keywords
            for (keyword in suspiciousKeywords) {
                if (host.contains(keyword) || path.contains(keyword)) {
                    score += 10
                    findings.add("Suspicious keyword: $keyword")
                }
            }

            // 5. Fake login patterns
            if (path.contains("login") || query.contains("login")) {
                score += 10
                findings.add("Fake login pattern detected")
            }

            // 6. Suspicious TLDs
            for (tld in suspiciousTlds) {
                if (host.endsWith(tld)) {
                    score += 20
                    findings.add("Suspicious TLD: $tld")
                    break
                }
            }

            // 7. Excessive query params
            if (query.isNotEmpty() && query.split("&").size > 5) {
                score += 10
                findings.add("Excessive query parameters")
            }

            // 8. @ symbol abuse
            if (uri.userInfo != null || urlStr.contains("@")) {
                score += 40
                findings.add("@ symbol abuse (credentials in URL)")
            }

            // 9. URL shortener
            val shorteners = listOf("bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly")
            if (shorteners.any { host.contains(it) }) {
                score += 10
                findings.add("URL Shortener used")
            }
            
            // 10. Multiple subdomains (e.g. login.paypal.com.scam.net)
            val parts = host.split(".")
            if (parts.size > 4) {
                score += 15
                findings.add("Excessive subdomains")
            }

            // 11. Encoded URLs and Redirect chains
            val decodedUrl = URLDecoder.decode(urlStr, "UTF-8")
            if (decodedUrl != urlStr && decodedUrl.contains("http", ignoreCase = true)) {
                score += 20
                findings.add("Encoded URL / Open Redirect pattern")
            }

        } catch (e: Exception) {
            findings.add("Unparseable URL")
            score += 50
        }

        return HeuristicAnalysisResult(score.coerceAtMost(100), findings)
    }
}
