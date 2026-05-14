package com.security.scanner.domain.model

import jakarta.persistence.*
import java.time.Instant

@Entity
@Table(name = "ingestion_metadata")
data class IngestionMetadata(
    @Id
    @Column(name = "filename", nullable = false, unique = true)
    val filename: String,

    @Column(name = "checksum", nullable = false)
    var checksum: String,

    @Column(name = "file_size", nullable = false)
    var fileSize: Long,

    @Column(name = "last_modified", nullable = false)
    var lastModified: Instant,

    @Column(name = "ingested_at", nullable = false)
    var ingestedAt: Instant = Instant.now()
)
