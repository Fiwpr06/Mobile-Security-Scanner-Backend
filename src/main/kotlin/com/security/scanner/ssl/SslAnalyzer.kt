package com.security.scanner.ssl

import com.security.scanner.domain.dto.SslAnalysisResult
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Component
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateNotYetValidException
import java.security.cert.X509Certificate
import javax.net.ssl.*
import java.net.URI

@Component
class SslAnalyzer {
    private val log = LoggerFactory.getLogger(javaClass)

    fun analyze(urlStr: String): SslAnalysisResult {
        if (!urlStr.startsWith("https", ignoreCase = true)) {
            return SslAnalysisResult(isValid = false, error = "Not HTTPS", errorType = "NO_HTTPS")
        }

        var isExpired = false
        var isSelfSigned = false
        var invalidHostname = false
        var issuer: String? = null
        var tlsVersion: String? = null
        var cipherSuite: String? = null

        // Custom trust manager to capture certificate details
        val trustManager = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                if (!chain.isNullOrEmpty()) {
                    val cert = chain[0]
                    issuer = cert.issuerX500Principal.name
                    try {
                        cert.checkValidity()
                    } catch (e: CertificateExpiredException) {
                        isExpired = true
                    } catch (e: CertificateNotYetValidException) {
                        isExpired = true
                    }
                    if (cert.issuerX500Principal == cert.subjectX500Principal) {
                        isSelfSigned = true
                    }
                }
            }
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        }

        return try {
            val sslContext = SSLContext.getInstance("TLS")
            sslContext.init(null, arrayOf<TrustManager>(trustManager), java.security.SecureRandom())

            val url = URI(urlStr).toURL()
            val connection = url.openConnection() as HttpsURLConnection
            connection.sslSocketFactory = sslContext.socketFactory
            connection.hostnameVerifier = HostnameVerifier { hostname, session -> 
                val isValid = HttpsURLConnection.getDefaultHostnameVerifier().verify(hostname, session)
                if (!isValid) invalidHostname = true
                true // Allow through to capture details
            }
            connection.connectTimeout = 5000
            connection.readTimeout = 5000
            connection.connect()

            cipherSuite = connection.cipherSuite
            val weakCipher = cipherSuite.contains("RC4") || cipherSuite.contains("DES") || 
                             cipherSuite.contains("MD5") || cipherSuite.contains("NULL") || 
                             cipherSuite.contains("EXPORT")
                             
            tlsVersion = if (cipherSuite.startsWith("TLS_")) "TLS" else "SSL"

            connection.disconnect()

            val hasError = isExpired || isSelfSigned || invalidHostname || weakCipher
            val errorType = when {
                isExpired -> "CERTIFICATE_EXPIRED"
                invalidHostname -> "INVALID_HOSTNAME"
                isSelfSigned -> "SELF_SIGNED"
                weakCipher -> "WEAK_CIPHER"
                else -> null
            }

            SslAnalysisResult(
                isValid = !hasError,
                isExpired = isExpired,
                isSelfSigned = isSelfSigned,
                isRevoked = false,
                invalidHostname = invalidHostname,
                weakCipher = weakCipher,
                tlsVersion = tlsVersion,
                cipherSuite = cipherSuite,
                issuer = issuer,
                error = if (hasError) "SSL Validation failed: $errorType" else null,
                errorType = errorType
            )
        } catch (e: SSLHandshakeException) {
            log.error("SSL Handshake error for $urlStr: ${e.message}")
            val msg = e.message ?: ""
            val isRevoked = msg.contains("revoked", ignoreCase = true)
            val errorType = when {
                isRevoked -> "CERTIFICATE_REVOKED"
                msg.contains("PKIX") -> "CERTIFICATE_INVALID_CHAIN"
                else -> "HANDSHAKE_FAILED"
            }
            
            SslAnalysisResult(
                isValid = false,
                isRevoked = isRevoked,
                error = e.message,
                errorType = errorType
            )
        } catch (e: java.net.UnknownHostException) {
            SslAnalysisResult(isValid = false, error = "DNS Resolution Failed: ${e.message}", errorType = "DNS_RESOLUTION_FAILED")
        } catch (e: java.net.SocketTimeoutException) {
            SslAnalysisResult(isValid = false, error = "Connection Timed Out", errorType = "CONNECTION_TIMEOUT")
        } catch (e: Exception) {
            log.error("SSL Analysis error for $urlStr: ${e.message}")
            SslAnalysisResult(isValid = false, error = e.message, errorType = "UNKNOWN_SSL_ERROR")
        }
    }
}
