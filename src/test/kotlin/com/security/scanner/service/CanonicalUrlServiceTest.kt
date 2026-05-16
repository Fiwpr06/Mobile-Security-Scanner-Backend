package com.security.scanner.service

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class CanonicalUrlServiceTest {

    private val service = CanonicalUrlService()

    @Test
    fun `should canonicalize simple http url`() {
        val result = service.canonicalize("http://example.com/path")
        assertNotNull(result)
        assertEquals("example.com", result!!.normalizedDomain)
        assertEquals("/path", result.normalizedPath)
        assertEquals("http://example.com/path", result.fullCanonicalUrl)
    }

    @Test
    fun `should normalize uppercase domain and trailing slash`() {
        val result = service.canonicalize("HTTPS://EXAMPLE.COM/PATH/")
        assertNotNull(result)
        assertEquals("example.com", result!!.normalizedDomain)
        assertEquals("/path", result.normalizedPath)
        assertEquals("https://example.com/path", result.fullCanonicalUrl)
    }

    @Test
    fun `should filter tracking parameters`() {
        val result = service.canonicalize("https://example.com/path?utm_source=ads&q=search&fbclid=123")
        assertNotNull(result)
        assertEquals("example.com", result!!.normalizedDomain)
        assertEquals("/path?q=search", result.normalizedPath)
        assertEquals("https://example.com/path?q=search", result.fullCanonicalUrl)
    }
}
