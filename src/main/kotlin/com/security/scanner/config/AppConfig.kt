package com.security.scanner.config

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Configuration
import org.springframework.stereotype.Component

@Component
@ConfigurationProperties(prefix = "app.third-party")
class ThirdPartyConfig {
    val googleSafeBrowsing = GoogleSafeBrowsingProperties()
    val virusTotal = VirusTotalProperties()
    val abuseIpDb = AbuseIpDbProperties()

    class GoogleSafeBrowsingProperties {
        var apiKey: String = ""
        var baseUrl: String = "https://safebrowsing.googleapis.com"
        var timeoutMs: Long = 5000L
        var enabled: Boolean = true
    }

    class VirusTotalProperties {
        var apiKey: String = ""
        var baseUrl: String = "https://www.virustotal.com"
        var timeoutMs: Long = 10000L
        var enabled: Boolean = true
    }

    class AbuseIpDbProperties {
        var apiKey: String = ""
        var baseUrl: String = "https://api.abuseipdb.com"
        var timeoutMs: Long = 5000L
        var enabled: Boolean = true
    }
}

@Component
@ConfigurationProperties(prefix = "app.scan")
class ScanConfig {
    val weights = ScanWeights()
    val thresholds = ScanThresholds()
    var parallelEnabled: Boolean = true
    var fastFailOnDangerous: Boolean = true

    class ScanWeights {
        var googleSafeBrowsing: Double = 0.5
        var virusTotal: Double = 0.3
        var abuseIpDb: Double = 0.2
    }

    class ScanThresholds {
        var safe: Int = 30
        var suspicious: Int = 60
    }
}
