package com.security.scanner.controller

import com.security.scanner.common.RequestIdHolder
import com.security.scanner.common.ValidUrl
import com.security.scanner.domain.dto.ScanRequest
import com.security.scanner.domain.dto.ScanResponse
import com.security.scanner.domain.dto.SuccessResponse
import com.security.scanner.service.ScanEngineService
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.security.SecurityRequirement
import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.validation.Valid
import org.slf4j.LoggerFactory
import org.springframework.http.ResponseEntity
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/api/v1/scan")
@Tag(name = "Scan", description = "URL threat scanning endpoints")
@SecurityRequirement(name = "bearerAuth")
class ScanController(
    private val scanEngineService: ScanEngineService
) {
    private val log = LoggerFactory.getLogger(javaClass)

    @PostMapping
    @Operation(
        summary = "Scan a URL for threats",
        description = """
            Analyzes a URL against multiple threat intelligence sources:
            - Google Safe Browsing (50% weight)
            - VirusTotal (30% weight)
            - AbuseIPDB (20% weight)
            
            Returns a risk score (0-100) and status: SAFE, SUSPICIOUS, or DANGEROUS.
        """
    )
    suspend fun scanUrl(
        @Valid @RequestBody request: ScanRequest,
        @AuthenticationPrincipal deviceId: String
    ): ResponseEntity<SuccessResponse<ScanResponse>> {
        val normalizedUrl = normalizeUrl(request.url)
        log.info("Scan request: url=$normalizedUrl device=$deviceId")

        // NOTE: By using `suspend fun` in Spring MVC, the Tomcat worker thread is
        // released back to the pool while the coroutine suspends during I/O.
        // This is a highly pragmatic upgrade that prevents thread starvation without
        // requiring a full WebFlux migration.
        val result = scanEngineService.scanUrl(normalizedUrl, deviceId)

        return ResponseEntity.ok(
            SuccessResponse(
                data = result,
                requestId = RequestIdHolder.get()
            )
        )
    }

    /**
     * Normalizes a URL by prepending https:// if no scheme is present.
     *
     * NOTE: This runs AFTER @Valid has already validated the URL against @ValidUrl.
     * The @ValidUrl annotation in ScanRequest handles scheme validation on raw input,
     * so we only need to handle the scheme-less case here (e.g., "example.com" -> "https://example.com").
     * Malicious schemes like "javascript:" or "ftp://" are rejected by @ValidUrl before reaching here.
     */
    private fun normalizeUrl(url: String): String {
        val trimmed = url.trim()
        return if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) {
            "https://$trimmed"
        } else trimmed
    }
}
