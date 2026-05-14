package com.security.scanner.domain.model

import jakarta.persistence.*
import java.time.Instant

@Entity
@Table(name = "dangerous_domains")
data class DangerousDomain(
    @Id
    @Column(name = "domain", nullable = false, unique = true)
    val domain: String,

    @Column(name = "reputation_score", nullable = false)
    var reputationScore: Int = 0,

    @Column(name = "malicious_url_count", nullable = false)
    var maliciousUrlCount: Long = 0,

    @Column(name = "is_blocked", nullable = false)
    var isBlocked: Boolean = false,

    @Column(name = "first_seen_at", nullable = false)
    val firstSeenAt: Instant = Instant.now(),

    @Column(name = "last_seen_at", nullable = false)
    var lastSeenAt: Instant = Instant.now()
)
