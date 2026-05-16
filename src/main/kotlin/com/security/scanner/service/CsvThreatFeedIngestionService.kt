package com.security.scanner.service

import com.security.scanner.domain.model.IngestionMetadata
import com.security.scanner.domain.model.MaliciousUrl
import com.security.scanner.repository.IngestionMetadataRepository
import com.security.scanner.repository.MaliciousUrlRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.withContext
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import java.io.File
import java.io.FileInputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant

@Service
class CsvThreatFeedIngestionService(
    private val metadataRepository: IngestionMetadataRepository,
    private val maliciousUrlRepository: MaliciousUrlRepository,
    private val canonicalUrlService: CanonicalUrlService,
    private val labelMapper: ThreatLabelMapper,
    private val bloomFilterService: BloomFilterService,
    private val threatConfidenceCalculator: ThreatConfidenceCalculator,
    private val exportService: ThreatExportService
) {
    private val log = LoggerFactory.getLogger(javaClass)
    private val batchSize = 2000

    suspend fun ingestDirectory(dirPath: String) = withContext(Dispatchers.IO) {
        val dir = File(dirPath)
        if (!dir.exists() || !dir.isDirectory) {
            log.warn("Ingestion directory not found: $dirPath")
            return@withContext
        }

        val csvFiles = dir.listFiles { _, name -> name.endsWith(".csv") } ?: emptyArray()
        
        for (file in csvFiles) {
            processFileIfNeeded(file)
        }
    }

    private suspend fun processFileIfNeeded(file: File) {
        val filename = file.name
        val currentSize = file.length()
        val currentModified = Instant.ofEpochMilli(file.lastModified())
        val checksum = calculateChecksum(file)

        val metadata = metadataRepository.findById(filename).orElse(null)

        if (metadata != null && metadata.checksum == checksum && metadata.fileSize == currentSize) {
            log.info("Skipping $filename - unchanged since last ingestion.")
            return
        }

        log.info("Starting ingestion for $filename")

        try {
            ingestFile(file)
            
            val newMetadata = IngestionMetadata(
                filename = filename,
                checksum = checksum,
                fileSize = currentSize,
                lastModified = currentModified,
                ingestedAt = Instant.now()
            )
            metadataRepository.save(newMetadata)
            log.info("Finished ingestion for $filename")
        } catch (e: Exception) {
            log.error("Error during ingestion of $filename", e)
        }
    }

    private suspend fun ingestFile(file: File) = withContext(Dispatchers.IO) {
        val filename = file.name
        var urlIndex = -1
        var labelIndex = -1
        
        var isHeaderProcessed = false

        file.inputStream().bufferedReader(StandardCharsets.UTF_8).useLines { lines ->
            val flow = lines.asFlow()

            flow.chunked(batchSize).collect { chunk ->
                if (!isHeaderProcessed) {
                    val header = chunk.first()
                    val cols = header.split(",")
                    urlIndex = cols.indexOfFirst { it.equals("url", ignoreCase = true) }
                    labelIndex = cols.indexOfFirst { it.equals("label", ignoreCase = true) || it.equals("type", ignoreCase = true) }
                    
                    if (urlIndex == -1) {
                        // fallback auto-detect based on data if header is missing
                        if (header.contains("http") || header.contains(".")) {
                            urlIndex = 0 // Assume first column is URL
                        }
                    }

                    isHeaderProcessed = true
                    // Process chunk without header
                    processChunk(chunk.drop(1), filename, urlIndex, labelIndex)
                } else {
                    processChunk(chunk, filename, urlIndex, labelIndex)
                }
            }
        }
    }

    private suspend fun processChunk(chunk: List<String>, filename: String, urlIdx: Int, labelIdx: Int) {
        val batch = mutableListOf<MaliciousUrl>()

        for (line in chunk) {
            if (line.isBlank()) continue
            
            val cols = line.split(",")
            val urlRaw = if (urlIdx >= 0 && urlIdx < cols.size) cols[urlIdx] else cols.firstOrNull() ?: continue
            val labelRaw = if (labelIdx >= 0 && labelIdx < cols.size) cols[labelIdx] else "malicious"

            if (urlRaw.isBlank() || urlRaw.equals("url", ignoreCase = true)) continue

            val canonicalData = canonicalUrlService.canonicalize(urlRaw)
            if (canonicalData == null) {
                exportService.exportFailedParsingRow(filename, line, "Canonicalization Failed")
                continue
            }

            val mappedThreat = labelMapper.mapLabel(labelRaw)
            
            val obs = ThreatObservation(filename, mappedThreat.isDangerous, mappedThreat.type)
            val confResult = threatConfidenceCalculator.calculate(listOf(obs))

            val entity = MaliciousUrl(
                urlHash = canonicalData.urlHash,
                url = canonicalData.fullCanonicalUrl,
                normalizedDomain = canonicalData.normalizedDomain,
                normalizedPath = canonicalData.normalizedPath,
                threatCategory = confResult.dominantThreatType,
                isDangerous = confResult.isDangerous,
                confidenceScore = confResult.confidenceScore,
                sources = filename
            )
            
            batch.add(entity)

            // Populate Bloom Filters
            if (entity.isDangerous) {
                bloomFilterService.addUrlHash(entity.urlHash)
                bloomFilterService.addDomain(entity.normalizedDomain)
            }
        }

        // Perform batch UPSERT
        if (batch.isNotEmpty()) {
            withContext(Dispatchers.IO) {
                batch.forEach { 
                    maliciousUrlRepository.upsertMaliciousUrl(it) 
                }
            }
        }
    }

    private fun calculateChecksum(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        FileInputStream(file).use { fis ->
            val byteArray = ByteArray(1024)
            var bytesCount = 0
            while (fis.read(byteArray).also { bytesCount = it } != -1) {
                digest.update(byteArray, 0, bytesCount)
            }
        }
        val bytes = digest.digest()
        return bytes.joinToString("") { "%02x".format(it) }
    }

    // Custom chunked flow operator
    private fun <T> Flow<T>.chunked(size: Int): Flow<List<T>> = flow {
        val chunk = mutableListOf<T>()
        collect { value ->
            chunk.add(value)
            if (chunk.size >= size) {
                emit(chunk.toList())
                chunk.clear()
            }
        }
        if (chunk.isNotEmpty()) {
            emit(chunk.toList())
        }
    }
}
