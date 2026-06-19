package com.security.scanner.repository

import com.security.scanner.domain.model.ScanResult
import com.security.scanner.domain.model.RiskStatus
import org.springframework.data.domain.Page
import org.springframework.data.domain.Pageable
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Modifying
import org.springframework.data.jpa.repository.Query
import org.springframework.stereotype.Repository
import java.time.Instant
import java.util.Optional
import java.util.UUID

@Repository
interface ScanResultRepository : JpaRepository<ScanResult, UUID> {
    fun findTopByUrlHashOrderByScannedAtDesc(urlHash: String): Optional<ScanResult>
    fun findByDeviceIdOrderByScannedAtDesc(deviceId: String, pageable: Pageable): Page<ScanResult>
    fun findByUserIdOrderByScannedAtDesc(userId: UUID, pageable: Pageable): Page<ScanResult>

    @Modifying
    @Query("UPDATE ScanResult s SET s.userId = :userId WHERE s.deviceId = :deviceId AND s.userId IS NULL")
    fun linkAnonymousScansToUser(deviceId: String, userId: UUID): Int

    @Query("SELECT s FROM ScanResult s WHERE s.status = :status ORDER BY s.scannedAt DESC")
    fun findByStatus(status: RiskStatus, pageable: Pageable): Page<ScanResult>

    @Query("SELECT COUNT(s) FROM ScanResult s WHERE s.deviceId = :deviceId AND s.scannedAt > :since")
    fun countRecentScansByDevice(deviceId: String, since: Instant): Long

    @Query("SELECT COUNT(s) FROM ScanResult s WHERE s.status = com.security.scanner.domain.model.RiskStatus.DANGEROUS AND s.scannedAt > :since")
    fun countDangerousScansSince(since: Instant): Long

    @Query("SELECT s.status, COUNT(s) FROM ScanResult s GROUP BY s.status")
    fun getStatusStatistics(): List<Array<Any>>
}
