package com.security.scanner.repository

import com.security.scanner.domain.model.FalseNegativeReport
import com.security.scanner.domain.model.ReportStatus
import org.springframework.data.domain.Page
import org.springframework.data.domain.Pageable
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository
import java.util.UUID

@Repository
interface FalseNegativeReportRepository : JpaRepository<FalseNegativeReport, UUID> {
    fun findByStatus(status: ReportStatus, pageable: Pageable): Page<FalseNegativeReport>
    fun findByDeviceId(deviceId: String, pageable: Pageable): Page<FalseNegativeReport>
    fun existsByUrlAndDeviceId(url: String, deviceId: String): Boolean
}
