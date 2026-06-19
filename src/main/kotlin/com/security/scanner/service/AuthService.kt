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
import com.security.scanner.repository.UserRepository

@Service
class AuthService(
    private val deviceRepository: DeviceRepository,
    private val userRepository: UserRepository,
    private val scanResultRepository: com.security.scanner.repository.ScanResultRepository,
    private val jwtService: JwtService
) {
    private val log = LoggerFactory.getLogger(javaClass)

    @Transactional
    fun registerDevice(request: DeviceRegistrationRequest): AuthResponse {
        // BUG FIX: The previous code called findByDeviceId() then existsByDeviceId() —
        // two separate DB queries for the same device. Fixed by tracking isNewDevice flag.
        var isNewDevice = false
        val device = try {
            deviceRepository.findByDeviceId(request.deviceId).orElseGet {
                isNewDevice = true
                log.info("Registering new device: ${request.deviceId}")
                deviceRepository.saveAndFlush(
                    Device(
                        deviceId = request.deviceId,
                        platform = request.platform,
                        appVersion = request.appVersion
                    )
                )
            }
        } catch (e: org.springframework.dao.DataIntegrityViolationException) {
            isNewDevice = false
            log.info("Device already registered concurrently: ${request.deviceId}")
            deviceRepository.findByDeviceId(request.deviceId).orElseThrow {
                IllegalStateException("Device ${request.deviceId} not found after DataIntegrityViolationException — this should never happen")
            }
        } catch (e: Exception) {
            log.error("Unexpected error registering device: ${request.deviceId}", e)
            throw e
        }

        // Only update lastSeen for already-existing devices, not newly registered ones.
        // @Modifying requires being inside a @Transactional context — this method is annotated,
        // so the call is safe.
        if (!isNewDevice) {
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

    private val passwordEncoder = org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder()

    @Transactional
    fun registerUser(request: com.security.scanner.domain.dto.AuthRequest): AuthResponse {
        if (userRepository.existsByUsername(request.username)) {
            throw IllegalArgumentException("Username already exists")
        }

        val user = com.security.scanner.domain.model.User(
            username = request.username,
            passwordHash = passwordEncoder.encode(request.password)
        )
        userRepository.saveAndFlush(user)

        val deviceId = request.deviceId ?: ("web-" + java.util.UUID.randomUUID().toString())
        
        val device = deviceRepository.findByDeviceId(deviceId).orElseGet {
            log.info("Registering new device during user signup: $deviceId")
            deviceRepository.saveAndFlush(
                Device(
                    deviceId = deviceId,
                    platform = "web",
                    appVersion = "1.0.0"
                )
            )
        }
        device.userId = user.id
        deviceRepository.save(device)

        val updatedScans = scanResultRepository.linkAnonymousScansToUser(deviceId, user.id)
        if (updatedScans > 0) {
            log.info("Linked $updatedScans anonymous scans from device $deviceId to user ${user.username}")
        }

        val token = jwtService.generateToken(deviceId, user.id.toString())

        return AuthResponse(
            accessToken = token,
            expiresIn = jwtService.getExpiration(),
            deviceId = deviceId,
            userId = user.id.toString(),
            username = user.username
        )
    }

    @Transactional
    fun loginUser(request: com.security.scanner.domain.dto.AuthRequest): AuthResponse {
        val user = userRepository.findByUsername(request.username)
            ?: throw IllegalArgumentException("Invalid username or password")

        if (!passwordEncoder.matches(request.password, user.passwordHash)) {
            throw IllegalArgumentException("Invalid username or password")
        }

        val deviceId = request.deviceId ?: ("web-" + java.util.UUID.randomUUID().toString())

        val device = deviceRepository.findByDeviceId(deviceId).orElseGet {
            log.info("Registering new device during user login: $deviceId")
            deviceRepository.saveAndFlush(
                Device(
                    deviceId = deviceId,
                    platform = "web",
                    appVersion = "1.0.0"
                )
            )
        }
        device.userId = user.id
        deviceRepository.save(device)

        val updatedScans = scanResultRepository.linkAnonymousScansToUser(deviceId, user.id)
        if (updatedScans > 0) {
            log.info("Linked $updatedScans anonymous scans from device $deviceId to user ${user.username}")
        }

        val token = jwtService.generateToken(deviceId, user.id.toString())

        return AuthResponse(
            accessToken = token,
            expiresIn = jwtService.getExpiration(),
            deviceId = deviceId,
            userId = user.id.toString(),
            username = user.username
        )
    }
}
