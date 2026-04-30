package com.security.scanner.repository

import com.security.scanner.domain.model.SecuritySnacksDomain
import org.springframework.data.domain.Pageable
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query
import org.springframework.stereotype.Repository

@Repository
interface SecuritySnacksRepository : JpaRepository<SecuritySnacksDomain, String> {
    fun findByDomain(domain: String): SecuritySnacksDomain?
    
    @Query("SELECT s.domain FROM SecuritySnacksDomain s WHERE s.isActive = true ORDER BY s.lastSeenAt DESC")
    fun findTopActiveDomains(pageable: Pageable): List<String>
}
