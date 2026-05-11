package com.security.scanner.controller

import com.security.scanner.domain.dto.FalseNegativeReportRequest
import com.security.scanner.domain.dto.ReportResponse
import com.security.scanner.domain.dto.SuccessResponse
import com.security.scanner.domain.dto.ThreatListResponse
import com.security.scanner.service.ThreatIntelligenceService
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.Parameter
import io.swagger.v3.oas.annotations.security.SecurityRequirement
import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.validation.Valid
import org.springframework.http.ResponseEntity
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/api/v1")
@Tag(name = "Threat Intelligence", description = "Threat reporting and intelligence endpoints")
@SecurityRequirement(name = "bearerAuth")
class ThreatIntelligenceController(
    private val threatIntelligenceService: ThreatIntelligenceService
) {

    @PostMapping("/report")
    @Operation(
        summary = "Report a false negative",
        description = "Report a URL that was marked as safe but turned out to be malicious"
    )
    fun reportFalseNegative(
        @Valid @RequestBody request: FalseNegativeReportRequest,
        @AuthenticationPrincipal deviceId: String
    ): ResponseEntity<SuccessResponse<ReportResponse>> {
        val response = threatIntelligenceService.submitFalseNegativeReport(request, deviceId)
        return ResponseEntity.ok(SuccessResponse(data = response))
    }

    @GetMapping("/threats/top")
    @Operation(
        summary = "Get top malicious URLs",
        description = "Returns a paginated list of most frequently detected malicious URLs"
    )
    fun getTopThreats(
        @Parameter(description = "Page number (0-based)") @RequestParam(defaultValue = "0") page: Int,
        @Parameter(description = "Page size") @RequestParam(defaultValue = "20") pageSize: Int
    ): ResponseEntity<SuccessResponse<ThreatListResponse>> {
        val response = threatIntelligenceService.getTopThreats(
            page = page.coerceAtLeast(0),
            pageSize = pageSize.coerceIn(1, 100)
        )
        return ResponseEntity.ok(SuccessResponse(data = response))
    }
}
