package com.security.scanner.common

import jakarta.validation.Constraint
import jakarta.validation.ConstraintValidator
import jakarta.validation.ConstraintValidatorContext
import jakarta.validation.Payload
import kotlin.reflect.KClass
import java.net.URI

@Target(AnnotationTarget.FIELD, AnnotationTarget.VALUE_PARAMETER)
@Retention(AnnotationRetention.RUNTIME)
@Constraint(validatedBy = [ValidUrlValidator::class])
annotation class ValidUrl(
    val message: String = "Invalid URL format",
    val groups: Array<KClass<*>> = [],
    val payload: Array<KClass<out Payload>> = []
)

class ValidUrlValidator : ConstraintValidator<ValidUrl, String> {

    private val allowedSchemes = setOf("http", "https")

    override fun isValid(value: String?, context: ConstraintValidatorContext?): Boolean {
        if (value.isNullOrBlank()) return false

        return try {
            val normalizedUrl = if (!value.startsWith("http://") && !value.startsWith("https://")) {
                "https://$value"
            } else value

            val uri = URI(normalizedUrl)
            val scheme = uri.scheme?.lowercase()
            val host = uri.host

            scheme in allowedSchemes &&
                !host.isNullOrBlank() &&
                !isPrivateOrLocalhost(host) &&
                host.contains(".")
        } catch (e: Exception) {
            false
        }
    }

    private fun isPrivateOrLocalhost(host: String): Boolean {
        val blocklist = setOf("localhost", "127.0.0.1", "0.0.0.0", "::1")
        if (host in blocklist) return true

        // Block private IP ranges
        val privatePatterns = listOf(
            Regex("^10\\..*"),
            Regex("^192\\.168\\..*"),
            Regex("^172\\.(1[6-9]|2[0-9]|3[01])\\..*"),
            Regex("^169\\.254\\..*"),  // Link-local
            Regex("^fc00:.*"),          // IPv6 unique local
            Regex("^fe80:.*")           // IPv6 link-local
        )
        return privatePatterns.any { it.matches(host) }
    }
}
