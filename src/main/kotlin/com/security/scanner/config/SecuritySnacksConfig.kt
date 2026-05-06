package com.security.scanner.config

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Configuration

@Configuration
@ConfigurationProperties(prefix = "security.snacks")
data class SecuritySnacksConfig(
    var feedUrls: List<String> = listOf(
        "https://raw.githubusercontent.com/DomainTools/SecuritySnacks/refs/heads/main/2023/Starbucks-NFT/starbucks-nft-campaign.csv"
    ),
    var cronSchedule: String = "0 0 2 * * ?", // Daily at 2 AM
    var connectionTimeout: Long = 10000,
    var enabled: Boolean = true
)
