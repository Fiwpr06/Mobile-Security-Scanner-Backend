package com.security.scanner.repository

import com.security.scanner.domain.model.DangerousDomain
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository

@Repository
interface DangerousDomainRepository : JpaRepository<DangerousDomain, String>
