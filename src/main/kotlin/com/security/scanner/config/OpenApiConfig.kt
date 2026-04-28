package com.security.scanner.config

import io.swagger.v3.oas.models.Components
import io.swagger.v3.oas.models.OpenAPI
import io.swagger.v3.oas.models.info.Contact
import io.swagger.v3.oas.models.info.Info
import io.swagger.v3.oas.models.info.License
import io.swagger.v3.oas.models.security.SecurityRequirement
import io.swagger.v3.oas.models.security.SecurityScheme
import io.swagger.v3.oas.models.servers.Server
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class OpenApiConfig {

    @Bean
    fun openApi(): OpenAPI {
        return OpenAPI()
            .info(
                Info()
                    .title("Mobile Security Scanner API")
                    .description(
                        """
                        Backend API for Mobile Security Scanner - An intelligent URL threat analysis system
                        powered by multiple threat intelligence sources including Google Safe Browsing,
                        VirusTotal, and AbuseIPDB.
                        
                        ## Authentication
                        1. Register your device: `POST /api/v1/auth/register`
                        2. Use the returned JWT token in subsequent requests as: `Authorization: Bearer <token>`
                        
                        ## Rate Limits
                        - 100 scans per device per hour
                        - 200 requests per IP per hour
                        """.trimIndent()
                    )
                    .version("1.0.0")
                    .contact(
                        Contact()
                            .name("Security Scanner Team")
                            .email("security@example.com")
                    )
                    .license(License().name("Apache 2.0"))
            )
            .addServersItem(Server().url("/").description("Current server"))
            .addSecurityItem(SecurityRequirement().addList("bearerAuth"))
            .components(
                Components()
                    .addSecuritySchemes(
                        "bearerAuth",
                        SecurityScheme()
                            .type(SecurityScheme.Type.HTTP)
                            .scheme("bearer")
                            .bearerFormat("JWT")
                            .description("JWT token obtained from /api/v1/auth/register")
                    )
            )
    }
}
