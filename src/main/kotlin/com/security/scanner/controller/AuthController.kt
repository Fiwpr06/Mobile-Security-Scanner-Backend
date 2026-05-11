package com.security.scanner.controller

import com.security.scanner.domain.dto.AuthResponse
import com.security.scanner.domain.dto.DeviceRegistrationRequest
import com.security.scanner.domain.dto.SuccessResponse
import com.security.scanner.service.AuthService
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.validation.Valid
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/api/v1/auth")
@Tag(name = "Authentication", description = "Device registration and JWT management")
class AuthController(private val authService: AuthService) {

    @PostMapping("/register")
    @Operation(
        summary = "Register device and get JWT",
        description = "Register a device by its unique ID and receive an access token"
    )
    fun register(
        @Valid @RequestBody request: DeviceRegistrationRequest
    ): ResponseEntity<SuccessResponse<AuthResponse>> {
        val response = authService.registerDevice(request)
        return ResponseEntity.ok(SuccessResponse(data = response))
    }
}
