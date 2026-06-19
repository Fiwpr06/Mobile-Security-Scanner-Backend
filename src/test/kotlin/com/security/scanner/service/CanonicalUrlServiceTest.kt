package com.security.scanner.service

import org.assertj.core.api.Assertions.assertThat
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
    fun `should normalize uppercase scheme and domain but preserve path casing`() {
        val result = service.canonicalize("HTTPS://EXAMPLE.COM/PATH/")
        assertNotNull(result)
        // Domain is normalized to lowercase
        assertEquals("example.com", result!!.normalizedDomain)
        // Path trailing slash is stripped, but path casing is PRESERVED (service does not lowercase paths)
        assertEquals("/PATH", result.normalizedPath)
        assertEquals("https://example.com/PATH", result.fullCanonicalUrl)
    }

    @Test
    fun `should filter tracking parameters`() {
        val result = service.canonicalize("https://example.com/path?utm_source=ads&q=search&fbclid=123")
        assertNotNull(result)
        assertEquals("example.com", result!!.normalizedDomain)
        assertEquals("/path?q=search", result.normalizedPath)
        assertEquals("https://example.com/path?q=search", result.fullCanonicalUrl)
    }

    @Test
    fun `should strip default port 443 from https URL`() {
        val result = service.canonicalize("https://example.com:443/page")
        assertNotNull(result)
        assertThat(result!!.fullCanonicalUrl).doesNotContain(":443")
        assertThat(result.fullCanonicalUrl).isEqualTo("https://example.com/page")
    }

    @Test
    fun `should strip default port 80 from http URL`() {
        val result = service.canonicalize("http://example.com:80/page")
        assertNotNull(result)
        assertThat(result!!.fullCanonicalUrl).doesNotContain(":80")
    }

    @Test
    fun `should preserve non-default port in URL`() {
        val result = service.canonicalize("https://example.com:8443/api")
        assertNotNull(result)
        assertThat(result!!.fullCanonicalUrl).isEqualTo("https://example.com:8443/api")
    }

    @Test
    fun `should add default path slash when missing`() {
        val result = service.canonicalize("https://example.com")
        assertNotNull(result)
        assertThat(result!!.normalizedPath).isEqualTo("/")
        assertThat(result.fullCanonicalUrl).isEqualTo("https://example.com/")
    }

    @Test
    fun `should produce consistent hash for same canonicalized URL`() {
        val result1 = service.canonicalize("https://EXAMPLE.COM/path/")
        val result2 = service.canonicalize("https://example.com/path")
        assertNotNull(result1)
        assertNotNull(result2)
        assertThat(result1!!.urlHash).isEqualTo(result2!!.urlHash)
    }

    @Test
    fun `should produce different hashes for different URLs`() {
        val result1 = service.canonicalize("https://example.com/path1")
        val result2 = service.canonicalize("https://example.com/path2")
        assertNotNull(result1)
        assertNotNull(result2)
        assertThat(result1!!.urlHash).isNotEqualTo(result2!!.urlHash)
    }

    @Test
    fun `should handle URL without scheme by prepending https`() {
        val result = service.canonicalize("example.com/some/path")
        assertNotNull(result)
        assertThat(result!!.normalizedDomain).isEqualTo("example.com")
    }

    @Test
    fun `should return null for completely invalid URL`() {
        val result = service.canonicalize("not a url !!!")
        // Should handle gracefully, either null or some result — must not throw
        // CanonicalUrlService returns null on exception
        // This is acceptable behavior
        assertThat(result == null || result.normalizedDomain.isNotBlank()).isTrue()
    }

    @Test
    fun `should remove all tracking params from URL`() {
        val url = "https://example.com/?utm_source=google&utm_medium=cpc&utm_campaign=test&gclid=abc&fbclid=xyz&q=hello"
        val result = service.canonicalize(url)
        assertNotNull(result)
        assertThat(result!!.fullCanonicalUrl).doesNotContain("utm_")
        assertThat(result.fullCanonicalUrl).doesNotContain("gclid")
        assertThat(result.fullCanonicalUrl).doesNotContain("fbclid")
        assertThat(result.fullCanonicalUrl).contains("q=hello")
    }
}
