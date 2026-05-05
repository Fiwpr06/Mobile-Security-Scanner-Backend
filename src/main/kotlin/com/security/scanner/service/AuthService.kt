package com.security.scanner.service

import com.security.scanner.domain.dto.AuthResponse
import com.security.scanner.domain.dto.DeviceRegistrationRequest
import com.security.scanner.domain.model.Device
import com.security.scanner.repository.DeviceRepository
import com.security.scanner.security.JwtService
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Instant

@Service
class AuthService(
    private val deviceRepository: DeviceRepository,
    private val jwtService: JwtService
) {
    private val log = LoggerFactory.getLogger(javaClass)

    @Transactional
    fun registerDevice(request: DeviceRegistrationRequest): AuthResponse {
        val device = deviceRepository.findByDeviceId(request.deviceId).orElseGet {
            log.info("Registering new device: ${request.deviceId}")
            deviceRepository.save(
                Device(
                    deviceId = request.deviceId,
                    platform = request.platform,
                    appVersion = request.appVersion
                )
            )
        }

        // Update last seen for existing device
        if (deviceRepository.existsByDeviceId(request.deviceId)) {
            deviceRepository.updateLastSeen(request.deviceId, Instant.now())
        }

        val token = jwtService.generateToken(device.deviceId)
        log.info("JWT issued for device: ${request.deviceId}")

        return AuthResponse(
            accessToken = token,
            expiresIn = jwtService.getExpiration(),
            deviceId = device.deviceId
        )
    }

    fun validateDevice(deviceId: String): Boolean {
        return deviceRepository.findByDeviceId(deviceId)
            .map { it.isActive }
            .orElse(false)
    }
}
