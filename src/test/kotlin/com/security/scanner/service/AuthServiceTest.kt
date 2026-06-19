package com.security.scanner.service

import com.security.scanner.domain.dto.DeviceRegistrationRequest
import com.security.scanner.domain.dto.AuthRequest
import com.security.scanner.domain.model.Device
import com.security.scanner.domain.model.User
import com.security.scanner.repository.DeviceRepository
import com.security.scanner.repository.UserRepository
import com.security.scanner.repository.ScanResultRepository
import com.security.scanner.security.JwtService
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.Mockito.never
import org.mockito.Mockito.verify
import org.mockito.Mockito.times
import org.mockito.kotlin.any
import org.mockito.kotlin.eq
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import org.springframework.dao.DataIntegrityViolationException
import java.time.Instant
import java.util.Optional

class AuthServiceTest {

    private lateinit var deviceRepository: DeviceRepository
    private lateinit var userRepository: UserRepository
    private lateinit var scanResultRepository: ScanResultRepository
    private lateinit var jwtService: JwtService
    private lateinit var authService: AuthService

    private val testDeviceId = "test-device-uuid-12345678"
    private val testToken = "eyJhbGciOiJIUzI1NiJ9.test.token"
    private val testExpiration = 86400000L

    @BeforeEach
    fun setUp() {
        deviceRepository = mock()
        userRepository = mock()
        scanResultRepository = mock()
        jwtService = mock()
        authService = AuthService(deviceRepository, userRepository, scanResultRepository, jwtService)
    }

    // ─── New Device Registration ──────────────────────────────────────────────

    @Test
    fun `should register new device and return JWT token`() {
        val request = DeviceRegistrationRequest(
            deviceId = testDeviceId,
            platform = "android",
            appVersion = "1.0.0"
        )
        val savedDevice = Device(deviceId = testDeviceId, platform = "android", appVersion = "1.0.0")

        whenever(jwtService.generateToken(testDeviceId)).thenReturn(testToken)
        whenever(jwtService.getExpiration()).thenReturn(testExpiration)
        whenever(deviceRepository.findByDeviceId(testDeviceId)).thenReturn(Optional.empty())
        // FIX: thenAnswer with invocation.getArgument can return null for generic JPA repository
        // methods. Use thenReturn(savedDevice) for a guaranteed non-null result.
        org.mockito.kotlin.doReturn(savedDevice).whenever(deviceRepository).saveAndFlush(org.mockito.kotlin.anyOrNull())

        val result = authService.registerDevice(request)

        assertThat(result.accessToken).isEqualTo(testToken)
        assertThat(result.deviceId).isEqualTo(testDeviceId)
        assertThat(result.expiresIn).isEqualTo(testExpiration)
        assertThat(result.tokenType).isEqualTo("Bearer")

        // Should save new device, NOT update lastSeen
        verify(deviceRepository, times(1)).saveAndFlush(org.mockito.kotlin.anyOrNull())
        verify(deviceRepository, never()).updateLastSeen(any(), any())
    }

    @Test
    fun `should return JWT for already-registered device and update lastSeen`() {
        val request = DeviceRegistrationRequest(
            deviceId = testDeviceId,
            platform = "web"
        )
        val existingDevice = Device(
            deviceId = testDeviceId,
            platform = "web",
            registeredAt = Instant.now().minusSeconds(3600)
        )

        whenever(jwtService.generateToken(testDeviceId)).thenReturn(testToken)
        whenever(jwtService.getExpiration()).thenReturn(testExpiration)
        whenever(deviceRepository.findByDeviceId(testDeviceId)).thenReturn(Optional.of(existingDevice))

        val result = authService.registerDevice(request)

        assertThat(result.accessToken).isEqualTo(testToken)
        assertThat(result.deviceId).isEqualTo(testDeviceId)

        // Should NOT save a new device, but SHOULD update lastSeen
        verify(deviceRepository, never()).saveAndFlush(org.mockito.kotlin.anyOrNull())
        verify(deviceRepository, times(1)).updateLastSeen(eq(testDeviceId), any())
    }

    // ─── Concurrent Registration Race Condition ───────────────────────────────

    @Test
    fun `should handle concurrent registration gracefully via DataIntegrityViolationException`() {
        val request = DeviceRegistrationRequest(deviceId = testDeviceId)
        val existingDevice = Device(deviceId = testDeviceId)

        whenever(jwtService.generateToken(testDeviceId)).thenReturn(testToken)
        whenever(jwtService.getExpiration()).thenReturn(testExpiration)

        // First call to findByDeviceId returns empty (triggers save attempt)
        // saveAndFlush throws DataIntegrityViolationException (concurrent insert)
        // Second call to findByDeviceId recovers the already-inserted device
        whenever(deviceRepository.findByDeviceId(testDeviceId))
            .thenReturn(Optional.empty<Device>())
            .thenReturn(Optional.of(existingDevice))
        org.mockito.kotlin.doThrow(DataIntegrityViolationException("Duplicate key: device_id"))
            .whenever(deviceRepository).saveAndFlush(org.mockito.kotlin.anyOrNull())

        val result = authService.registerDevice(request)

        assertThat(result.deviceId).isEqualTo(testDeviceId)
        assertThat(result.accessToken).isEqualTo(testToken)

        // Two findByDeviceId calls: initial + recovery after DataIntegrityViolationException
        verify(deviceRepository, times(2)).findByDeviceId(testDeviceId)
        // Not a new device (caught exception → isNewDevice = false) → updateLastSeen SHOULD be called
        verify(deviceRepository, org.mockito.kotlin.times(1)).updateLastSeen(org.mockito.kotlin.eq(testDeviceId), org.mockito.kotlin.anyOrNull())
    }

    // ─── Device Validation ────────────────────────────────────────────────────

    @Test
    fun `validateDevice should return true for active device`() {
        val device = Device(deviceId = testDeviceId, isActive = true)
        whenever(deviceRepository.findByDeviceId(testDeviceId)).thenReturn(Optional.of(device))

        assertThat(authService.validateDevice(testDeviceId)).isTrue()
    }

    @Test
    fun `validateDevice should return false for inactive device`() {
        val device = Device(deviceId = testDeviceId, isActive = false)
        whenever(deviceRepository.findByDeviceId(testDeviceId)).thenReturn(Optional.of(device))

        assertThat(authService.validateDevice(testDeviceId)).isFalse()
    }

    @Test
    fun `validateDevice should return false for unknown device`() {
        whenever(deviceRepository.findByDeviceId(testDeviceId)).thenReturn(Optional.empty())

        assertThat(authService.validateDevice(testDeviceId)).isFalse()
    }

    // ─── Request Validation ───────────────────────────────────────────────────

    @Test
    fun `should generate token with correct deviceId from request`() {
        val request = DeviceRegistrationRequest(
            deviceId = testDeviceId,
            platform = "ios",
            appVersion = "2.0.0"
        )
        val savedDevice = Device(deviceId = testDeviceId, platform = "ios", appVersion = "2.0.0")

        whenever(jwtService.generateToken(testDeviceId)).thenReturn(testToken)
        whenever(jwtService.getExpiration()).thenReturn(testExpiration)
        whenever(deviceRepository.findByDeviceId(testDeviceId)).thenReturn(Optional.empty())
        org.mockito.kotlin.doReturn(savedDevice).whenever(deviceRepository).saveAndFlush(org.mockito.kotlin.anyOrNull())

        authService.registerDevice(request)

        verify(jwtService).generateToken(testDeviceId)
    }

    // ─── User Registration ────────────────────────────────────────────────────
    @Test
    fun `should register user, link device, and link anonymous scans`() {
        val request = AuthRequest(
            username = "newuser",
            password = "securepassword",
            deviceId = "test-device"
        )
        val user = User(username = "newuser", passwordHash = "encoded-password")
        val device = Device(deviceId = "test-device")

        whenever(userRepository.existsByUsername("newuser")).thenReturn(false)
        org.mockito.kotlin.doReturn(user).whenever(userRepository).saveAndFlush(org.mockito.kotlin.anyOrNull())
        whenever(deviceRepository.findByDeviceId("test-device")).thenReturn(Optional.of(device))
        whenever(scanResultRepository.linkAnonymousScansToUser(eq("test-device"), org.mockito.kotlin.anyOrNull())).thenReturn(5)
        whenever(jwtService.generateToken(eq("test-device"), org.mockito.kotlin.anyOrNull())).thenReturn(testToken)
        whenever(jwtService.getExpiration()).thenReturn(testExpiration)

        val result = authService.registerUser(request)

        assertThat(result.accessToken).isEqualTo(testToken)
        assertThat(result.username).isEqualTo("newuser")

        verify(userRepository).saveAndFlush(org.mockito.kotlin.anyOrNull<User>())
        verify(deviceRepository).save(device)
        verify(scanResultRepository).linkAnonymousScansToUser(eq("test-device"), org.mockito.kotlin.anyOrNull())
        assertThat(device.userId).isNotNull()
    }

    // ─── User Login ───────────────────────────────────────────────────────────
    @Test
    fun `should login user, link device, and link anonymous scans`() {
        val request = AuthRequest(
            username = "existinguser",
            password = "correctpassword",
            deviceId = "test-device"
        )
        val encoder = org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder()
        val encodedPassword = encoder.encode("correctpassword")
        val user = User(username = "existinguser", passwordHash = encodedPassword)
        val device = Device(deviceId = "test-device")

        whenever(userRepository.findByUsername("existinguser")).thenReturn(user)
        whenever(deviceRepository.findByDeviceId("test-device")).thenReturn(Optional.of(device))
        whenever(scanResultRepository.linkAnonymousScansToUser(eq("test-device"), org.mockito.kotlin.anyOrNull())).thenReturn(3)
        whenever(jwtService.generateToken(eq("test-device"), org.mockito.kotlin.anyOrNull())).thenReturn(testToken)
        whenever(jwtService.getExpiration()).thenReturn(testExpiration)

        val result = authService.loginUser(request)

        assertThat(result.accessToken).isEqualTo(testToken)
        assertThat(result.userId).isEqualTo(user.id.toString())

        verify(deviceRepository).save(device)
        verify(scanResultRepository).linkAnonymousScansToUser(eq("test-device"), org.mockito.kotlin.anyOrNull())
        assertThat(device.userId).isEqualTo(user.id)
    }
}
