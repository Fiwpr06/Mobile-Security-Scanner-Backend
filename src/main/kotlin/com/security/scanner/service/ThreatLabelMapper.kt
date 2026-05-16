package com.security.scanner.service

import org.springframework.stereotype.Service

@Service
class ThreatLabelMapper {

    // Map common dataset labels to unified types
    fun mapLabel(rawLabel: String): MappedThreat {
        val normalized = rawLabel.trim().lowercase()

        return when (normalized) {
            "phishing", "phish" -> MappedThreat("PHISHING", true)
            "malware", "malicious", "bad", "1" -> MappedThreat("MALWARE", true)
            "defacement", "defaced" -> MappedThreat("DEFACEMENT", true)
            "spam" -> MappedThreat("SPAM", true)
            "suspicious", "susp" -> MappedThreat("SUSPICIOUS", true)
            "safe", "benign", "good", "0" -> MappedThreat("SAFE", false)
            else -> {
                // If the dataset typically only contains bad URLs but label is weird, assume suspicious
                MappedThreat("UNKNOWN", true) 
            }
        }
    }
}

data class MappedThreat(
    val type: String,
    val isDangerous: Boolean
)
