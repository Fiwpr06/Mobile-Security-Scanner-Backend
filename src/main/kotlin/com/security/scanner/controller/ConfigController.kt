package com.security.scanner.controller

import com.security.scanner.domain.dto.AppConfigResponse
import com.security.scanner.domain.dto.SuccessResponse
import com.security.scanner.service.ConfigService
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.tags.Tag
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/v1/config")
@Tag(name = "Config", description = "Dynamic app configuration")
class ConfigController(private val configService: ConfigService) {

    @GetMapping
    @Operation(
        summary = "Get dynamic app configuration",
        description = "Returns runtime configuration including scoring weights, timeouts, feature flags, and maintenance status"
    )
    fun getConfig(): ResponseEntity<SuccessResponse<AppConfigResponse>> {
        return ResponseEntity.ok(SuccessResponse(data = configService.getAppConfig()))
    }
}
