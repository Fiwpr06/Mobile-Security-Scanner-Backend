package com.security.scanner.repository

import com.security.scanner.domain.model.IngestionMetadata
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository

@Repository
interface IngestionMetadataRepository : JpaRepository<IngestionMetadata, String>
