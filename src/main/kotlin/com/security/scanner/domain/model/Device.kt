package com.security.scanner.domain.model

import jakarta.persistence.*
import java.time.Instant
import java.util.UUID

@Entity
@Table(name = "devices")
data class Device(
    @Id
    @Column(name = "id", nullable = false)
    val id: UUID = UUID.randomUUID(),

    @Column(name = "device_id", unique = true, nullable = false)
    val deviceId: String,

    @Column(name = "user_id")
    var userId: UUID? = null,

    @Column(name = "platform")
    val platform: String? = null,

    @Column(name = "app_version")
    val appVersion: String? = null,

    @Column(name = "registered_at", nullable = false)
    val registeredAt: Instant = Instant.now(),

    @Column(name = "last_seen_at")
    var lastSeenAt: Instant = Instant.now(),

    @Column(name = "is_active", nullable = false)
    var isActive: Boolean = true,

    @Column(name = "scan_count", nullable = false)
    var scanCount: Long = 0L
)
