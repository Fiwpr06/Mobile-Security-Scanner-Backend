package com.security.scanner

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.cache.annotation.EnableCaching
import org.springframework.scheduling.annotation.EnableAsync
import org.springframework.scheduling.annotation.EnableScheduling

@SpringBootApplication
@EnableCaching
@EnableAsync
@EnableScheduling
class MobileSecurityScannerApplication

fun main(args: Array<String>) {
    runApplication<MobileSecurityScannerApplication>(*args)
}
