package com.security.scanner.service

import com.security.scanner.config.DatasetConfidenceConfig
import org.springframework.stereotype.Service

data class ThreatConfidenceResult(
    val confidenceScore: Double,
    val isDangerous: Boolean,
    val requiresVerification: Boolean,
    val dominantThreatType: String?
)

@Service
class ThreatConfidenceCalculator(
    private val config: DatasetConfidenceConfig
) {

    fun calculate(observations: List<ThreatObservation>): ThreatConfidenceResult {
        if (observations.isEmpty()) {
            return ThreatConfidenceResult(0.0, false, false, null)
        }

        var totalDangerousWeight = 0.0
        var totalSafeWeight = 0.0
        val threatTypes = mutableMapOf<String, Double>()

        for (obs in observations) {
            val weight = config.sourceWeights[obs.sourceDataset] ?: config.defaultWeight
            if (obs.isDangerous) {
                totalDangerousWeight += weight
                val currentThreatWeight = threatTypes.getOrDefault(obs.threatType, 0.0)
                threatTypes[obs.threatType] = currentThreatWeight + weight
            } else {
                totalSafeWeight += weight
            }
        }

        // Case 1: All sources dangerous
        if (totalSafeWeight == 0.0 && totalDangerousWeight > 0.0) {
            val dominantThreat = threatTypes.maxByOrNull { it.value }?.key
            return ThreatConfidenceResult(
                confidenceScore = Math.min(1.0, totalDangerousWeight),
                isDangerous = true,
                requiresVerification = false,
                dominantThreatType = dominantThreat
            )
        }

        // Case 2: All sources safe
        if (totalDangerousWeight == 0.0 && totalSafeWeight > 0.0) {
            return ThreatConfidenceResult(
                confidenceScore = Math.min(1.0, totalSafeWeight),
                isDangerous = false,
                requiresVerification = false,
                dominantThreatType = "SAFE"
            )
        }

        // Case 3: Mixed -> Calculate weighted confidence
        val totalWeight = totalDangerousWeight + totalSafeWeight
        val dangerousConfidence = totalDangerousWeight / totalWeight
        
        val dominantThreat = threatTypes.maxByOrNull { it.value }?.key ?: "SUSPICIOUS"

        if (dangerousConfidence >= config.dangerousThreshold) {
            return ThreatConfidenceResult(
                confidenceScore = dangerousConfidence,
                isDangerous = true,
                requiresVerification = false,
                dominantThreatType = dominantThreat
            )
        } else {
            // Suspicious / Conflicted -> export for external verification
            return ThreatConfidenceResult(
                confidenceScore = dangerousConfidence,
                isDangerous = false, // Not high enough to fast-fail safely
                requiresVerification = true,
                dominantThreatType = "SUSPICIOUS"
            )
        }
    }
}

data class ThreatObservation(
    val sourceDataset: String,
    val isDangerous: Boolean,
    val threatType: String
)
