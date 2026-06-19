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
        httpServletRequest: jakarta.servlet.http.HttpServletRequest
    ): ResponseEntity<SuccessResponse<ScanResponse>> {
        val deviceId = httpServletRequest.getAttribute("deviceId") as String?
        val userIdStr = httpServletRequest.getAttribute("userId") as String?
        val userId = userIdStr?.let { java.util.UUID.fromString(it) }

        if (deviceId == null && userId == null) {
            return ResponseEntity.status(401).build()
        }
        val actualDeviceId = deviceId ?: "web-user-$userId"

        val normalizedUrl = normalizeUrl(request.url)
        log.info("Scan request: url=$normalizedUrl device=$actualDeviceId user=$userId")

        val result = scanEngineService.scanUrl(normalizedUrl, actualDeviceId, userId)

        return ResponseEntity.ok(
            SuccessResponse(
                data = result,
                requestId = RequestIdHolder.get()
            )
        )
    }

    @GetMapping("/me")
    @Operation(summary = "Get user/device scans", description = "Get scan history for the logged in user or device")
    suspend fun getUserScans(
        httpServletRequest: jakarta.servlet.http.HttpServletRequest,
        @RequestParam(defaultValue = "0") page: Int,
        @RequestParam(defaultValue = "20") size: Int
    ): ResponseEntity<SuccessResponse<org.springframework.data.domain.Page<ScanResponse>>> {
        val userIdStr = httpServletRequest.getAttribute("userId") as String?
        val deviceId = httpServletRequest.getAttribute("deviceId") as String?

        if (userIdStr == null && deviceId == null) {
            return ResponseEntity.status(401).build()
        }

        val scans = if (userIdStr != null) {
            val userId = java.util.UUID.fromString(userIdStr)
            scanEngineService.getUserScans(userId, page, size)
        } else {
            scanEngineService.getDeviceScans(deviceId!!, page, size)
        }
        
        return ResponseEntity.ok(SuccessResponse(data = scans))
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
