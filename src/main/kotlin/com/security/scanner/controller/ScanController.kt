package com.security.scanner.controller

import com.security.scanner.common.RequestIdHolder
import com.security.scanner.domain.dto.ScanRequest
import com.security.scanner.domain.dto.ScanResponse
import com.security.scanner.domain.dto.SuccessResponse
import com.security.scanner.service.ScanEngineService
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.security.SecurityRequirement
import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.validation.Valid
import kotlinx.coroutines.runBlocking
import org.slf4j.LoggerFactory
import org.springframework.http.ResponseEntity
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.web.bind.annotation.*
import java.net.URI

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
    fun scanUrl(
        @Valid @RequestBody request: ScanRequest,
        @AuthenticationPrincipal deviceId: String
    ): ResponseEntity<SuccessResponse<ScanResponse>> {
        val normalizedUrl = normalizeUrl(request.url)
        log.info("Scan request: url=$normalizedUrl device=$deviceId")

        // Run coroutine in blocking context (controller is servlet-based)
        val result = runBlocking {
            scanEngineService.scanUrl(normalizedUrl, deviceId)
        }

        return ResponseEntity.ok(
            SuccessResponse(
                data = result,
                requestId = RequestIdHolder.get()
            )
        )
    }

    private fun normalizeUrl(url: String): String {
        val trimmed = url.trim()
        return if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) {
            "https://$trimmed"
        } else trimmed
    }
}
