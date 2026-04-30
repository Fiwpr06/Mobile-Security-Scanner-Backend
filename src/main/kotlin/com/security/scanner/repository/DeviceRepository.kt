package com.security.scanner.repository

import com.security.scanner.domain.model.Device
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Modifying
import org.springframework.data.jpa.repository.Query
import org.springframework.stereotype.Repository
import java.time.Instant
import java.util.Optional
import java.util.UUID

@Repository
interface DeviceRepository : JpaRepository<Device, UUID> {
    fun findByDeviceId(deviceId: String): Optional<Device>
    fun existsByDeviceId(deviceId: String): Boolean

    @Modifying
    @Query("UPDATE Device d SET d.lastSeenAt = :lastSeen, d.scanCount = d.scanCount + 1 WHERE d.deviceId = :deviceId")
    fun updateLastSeenAndIncrementScanCount(deviceId: String, lastSeen: Instant)

    @Modifying
    @Query("UPDATE Device d SET d.lastSeenAt = :lastSeen WHERE d.deviceId = :deviceId")
    fun updateLastSeen(deviceId: String, lastSeen: Instant)
}
