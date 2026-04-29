package com.security.scanner.domain.model

import jakarta.persistence.*
import java.time.Instant

@Entity
@Table(name = "security_snacks_domains")
data class SecuritySnacksDomain(
    @Id
    @Column(name = "domain", nullable = false, unique = true)
    val domain: String,

    @Column(name = "added_at", nullable = false)
    val addedAt: Instant = Instant.now(),

    @Column(name = "last_seen_at", nullable = false)
    var lastSeenAt: Instant = Instant.now(),

    @Column(name = "is_active", nullable = false)
    var isActive: Boolean = true
)
