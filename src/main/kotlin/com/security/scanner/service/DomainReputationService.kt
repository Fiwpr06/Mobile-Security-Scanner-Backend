package com.security.scanner.service

import com.security.scanner.domain.model.DangerousDomain
import com.security.scanner.repository.DangerousDomainRepository
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Instant

@Service
class DomainReputationService(
    private val dangerousDomainRepository: DangerousDomainRepository,
    private val redisCacheService: RedisThreatCacheService
) {
    private val log = LoggerFactory.getLogger(javaClass)
    private val BLOCK_THRESHOLD = 50 // If domain has 50+ malicious URLs, block entire domain

    @Transactional
    fun incrementDomainMaliciousCount(domain: String, increment: Long = 1) {
        val entity = dangerousDomainRepository.findById(domain).orElse(
            DangerousDomain(domain = domain)
        )

        entity.maliciousUrlCount += increment
        entity.reputationScore -= increment.toInt()
        entity.lastSeenAt = Instant.now()

        if (!entity.isBlocked && entity.maliciousUrlCount >= BLOCK_THRESHOLD) {
            log.warn("Domain $domain exceeded malicious threshold. Blocking entirely.")
            entity.isBlocked = true
            redisCacheService.cacheDangerousDomain(domain)
        }

        dangerousDomainRepository.save(entity)
    }

    fun isDomainBlocked(domain: String): Boolean {
        // First check fast cache
        if (redisCacheService.isDomainBlocked(domain)) {
            return true
        }

        // Fallback to DB
        val entity = dangerousDomainRepository.findById(domain).orElse(null)
        if (entity?.isBlocked == true) {
            redisCacheService.cacheDangerousDomain(domain)
            return true
        }
        return false
    }
}
