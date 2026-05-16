package com.security.scanner.service

import com.google.common.hash.BloomFilter
import com.google.common.hash.Funnels
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicReference

@Service
class BloomFilterService {
    private val log = LoggerFactory.getLogger(javaClass)

    // Expected elements: 10 million, False Positive probability: 1%
    private val expectedInsertions = 10_000_000
    private val fpp = 0.01

    private val urlFilter = AtomicReference(createNewFilter())
    private val domainFilter = AtomicReference(createNewFilter())

    private fun createNewFilter(): BloomFilter<CharSequence> {
        return BloomFilter.create(
            Funnels.stringFunnel(StandardCharsets.UTF_8),
            expectedInsertions,
            fpp
        )
    }

    fun addUrlHash(hash: String) {
        urlFilter.get().put(hash)
    }

    fun addDomain(domain: String) {
        domainFilter.get().put(domain)
    }

    fun mightContainUrlHash(hash: String): Boolean {
        return urlFilter.get().mightContain(hash)
    }

    fun mightContainDomain(domain: String): Boolean {
        return domainFilter.get().mightContain(domain)
    }

    fun resetFilters() {
        log.info("Resetting Bloom Filters")
        urlFilter.set(createNewFilter())
        domainFilter.set(createNewFilter())
    }
}
