package com.security.scanner.service

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Service
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import jakarta.annotation.PostConstruct

@Service
class ThreatExportService(
    @Value("\${threat.intelligence.export.dir:data/exports}") private val exportDir: String
) {
    private val log = LoggerFactory.getLogger(javaClass)

    @PostConstruct
    fun init() {
        val dir = File(exportDir)
        if (!dir.exists()) {
            dir.mkdirs()
        }
    }

    suspend fun exportConflictedUrl(url: String, score: Double, sources: String) = withContext(Dispatchers.IO) {
        appendToFile("conflicted_urls.txt", "$url,$score,$sources\n")
    }

    suspend fun exportLowConfidenceUrl(url: String, score: Double, sources: String) = withContext(Dispatchers.IO) {
        appendToFile("low_confidence_urls.txt", "$url,$score,$sources\n")
    }

    suspend fun exportFailedParsingRow(filename: String, row: String, reason: String) = withContext(Dispatchers.IO) {
        appendToFile("failed_parsing_rows.txt", "[$filename] $reason: $row\n")
    }

    private fun appendToFile(filename: String, line: String) {
        try {
            val file = File(exportDir, filename)
            Files.writeString(
                file.toPath(),
                line,
                StandardOpenOption.CREATE,
                StandardOpenOption.APPEND
            )
        } catch (e: Exception) {
            log.error("Failed to write export file $filename", e)
        }
    }
}
