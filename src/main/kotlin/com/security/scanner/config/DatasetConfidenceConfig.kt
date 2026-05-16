package com.security.scanner.config

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Configuration

@Configuration
@ConfigurationProperties(prefix = "threat.intelligence.confidence")
class DatasetConfidenceConfig {
    var defaultWeight: Double = 0.5
    var sourceWeights: Map<String, Double> = mapOf(
        "Malicious URL v3.csv" to 1.0,
        "phishing_site_urls.csv" to 0.9,
        "malicious_phish.csv" to 0.8,
        "phishing_url_dataset_unique.csv" to 0.9,
        "user_imported.txt" to 0.5
    )
    
    var dangerousThreshold: Double = 0.75
}
