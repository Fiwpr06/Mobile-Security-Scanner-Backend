# 🔐 Mobile Security Scanner — Backend

> **Production-Grade Kotlin/Spring Boot backend** for intelligent URL threat analysis.  
> Integrates Google Safe Browsing, AbuseIPDB, VirusTotal, and Offline Threat Feeds  
> with a **Priority-Based Sequential Scanning Pipeline**, custom weighted scoring, variable Redis caching, and reactive structured concurrency.

---

## 📐 Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        Android App                              │
└───────────────────────────┬─────────────────────────────────────┘
                            │ HTTPS
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Nginx Reverse Proxy                          │
│           Rate Limiting | SSL Termination | Security Headers    │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│               Spring Boot Application (Kotlin)                  │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────┐   │
│  │ Auth API     │  │  Scan API    │  │ Threat Intel API   │   │
│  │ /auth/register│  │  /scan       │  │ /stats, /search    │   │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬─────────┘   │
│         │                 │                       │             │
│  ┌──────▼─────────────────▼───────────────────────▼─────────┐  │
│  │                  Service Layer                            │  │
│  │  AuthService  │ ScanEngineService │ ThreatIntelService   │  │
│  └──────────────────────┬──────────────────────────────────┘  │
│                         │ Sequential Pipeline (Non-Blocking)   │
│                         ▼                                     │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │ 1. Offline Threat Shield (Bloom Filter + DB Lookup)     │  │
│  └──────────────────────┬──────────────────────────────────┘  │
│                         ▼ (Bloom Filter Miss)                 │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │ 2. Google Safe Browsing (Fast Return if Malicious)       │  │
│  └──────────────────────┬──────────────────────────────────┘  │
│                         ▼ (Google Safe / Unknown)             │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │ 3. AbuseIPDB Reputation Scan (Reputation Confidence)     │  │
│  └──────────────────────┬──────────────────────────────────┘  │
│                         ▼ (Conditional VT Escalation)         │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │ 4. VirusTotal Scanner (Deep Analysis for Gray URLs)     │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌─────────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │   PostgreSQL    │  │    Redis     │  │   Prometheus +   │  │
│  │ (Async Adapter) │  │  (Jackson +   │  │     Grafana      │  │
│  │                 │  │ Variable TTL)│  │  (Monitoring)    │  │
│  └─────────────────┘  └──────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Package Structure (Clean Layered Architecture)

```
src/main/kotlin/com/security/scanner/
├── MobileSecurityScannerApplication.kt
├── controller/          # REST API controllers (Presentation Layer)
│   ├── AuthController.kt
│   ├── ScanController.kt          # Suspend Controller (no runBlocking)
│   ├── ConfigController.kt
│   └── ThreatIntelligenceController.kt
├── service/             # Business Logic & Orchestration
│   ├── AuthService.kt
│   ├── ScanEngineService.kt       # Sequential Scanning Pipeline
│   ├── ConfigService.kt
│   ├── ThreatIntelligenceService.kt
│   ├── CanonicalUrlService.kt     # URL normalization & Punycode conversion
│   ├── BloomFilterService.kt      # Guava Bloom Filter for offline threat lookup
│   ├── CsvThreatFeedIngestionService.kt # Ingests threat intel feeds from CSV
│   ├── DomainReputationService.kt  # Aggregates reputation score at domain level
│   ├── OfflineThreatIntelService.kt # Local fast-path threat checker
│   ├── RedisThreatCacheService.kt  # Variable TTL Redis Cache (Jackson serialize)
│   └── ThreatExportService.kt     # Bulk export threat intel data
├── ssl/                 # SSL/TLS Analysis Module
│   └── SslAnalyzer.kt
├── heuristic/           # Heuristic Detection Engine
│   └── HeuristicAnalyzer.kt
├── domain/              # Domain Models, Entities & DTOs
│   ├── model/           # JPA Entities
│   │   ├── Device.kt
│   │   ├── ScanResult.kt
│   │   ├── MaliciousUrl.kt       # Redesigned with canonical fields & indexes
│   │   ├── DangerousDomain.kt    # Aggregated domain-level reputation metrics
│   │   ├── IngestionMetadata.kt  # Tracks ingested feed file status & checksums
│   │   └── FalseNegativeReport.kt
│   └── dto/             # Request & Response schemas
│       └── Dtos.kt
├── repository/          # Database Persistence
│   ├── DeviceRepository.kt
│   ├── ScanResultRepository.kt
│   ├── MaliciousUrlRepository.kt  # Native Postgres upsert query (ON CONFLICT)
│   ├── DangerousDomainRepository.kt
│   ├── IngestionMetadataRepository.kt
│   ├── ScanRepositoryAdapter.kt   # Thread-isolated non-blocking JPA Adapter
│   └── FalseNegativeReportRepository.kt
├── external/            # Third-Party Integrations
│   └── integration/
│       ├── ThreatIntelligencePort.kt  # Integrates ThreatIntelStatus Enum
│       ├── GoogleSafeBrowsingClient.kt
│       ├── VirusTotalClient.kt        # Custom 404 UNKNOWN state (Zero-day protection)
│       └── AbuseIpDbClient.kt
├── security/            # Authentication, Filters & Rate Limiter
│   ├── JwtService.kt
│   ├── JwtAuthenticationFilter.kt
│   └── RateLimitingFilter.kt      # Redis INCR/TTL atomic rate limiter
├── config/              # Spring Boot Configurations
│   ├── SecurityConfig.kt
│   ├── AppConfig.kt
│   ├── DatasetConfidenceConfig.kt # Dynamic offline data source trust metrics
│   ├── WebClientConfig.kt
│   └── OpenApiConfig.kt
└── common/              # Shared Utilities & Base Classes
    ├── BackgroundJobScope.kt      # Lifecycle-aware supervisor coroutine scope
    ├── GlobalExceptionHandler.kt
    ├── RequestLoggingFilter.kt
    └── UrlValidator.kt
```

---

## 🚀 Quick Start (Local Development)

### Prerequisites
- Docker & Docker Compose
- JDK 21 (for running locally)
- OpenSSL (for SSL cert generation)

### 1. Clone & Configure

```bash
git clone <repo-url> mobile-security-scanner
cd mobile-security-scanner

# Create your .env file
cp .env.example .env
```

Edit `.env` and fill in:
- `JWT_SECRET` (generate with `openssl rand -base64 64`)
- API keys: `GOOGLE_SAFE_BROWSING_API_KEY`, `VIRUS_TOTAL_API_KEY`, `ABUSE_IPDB_API_KEY`

### 2. Generate SSL Certificate (local dev)

```bash
bash scripts/generate-ssl.sh
```

### 3. Start All Services

```bash
docker-compose up -d
```

This starts: **App + Nginx + PostgreSQL + Redis + Prometheus + Grafana**

### 4. Verify

```bash
# Health check
curl http://localhost:8080/actuator/health

# Swagger UI
open http://localhost:8080/swagger-ui.html
```

---

## 📡 API Reference

### Authentication

**POST** `/api/v1/auth/register` — Register device & get JWT (uses atomic `isNewDevice` check)

```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"deviceId": "android-unique-device-id-here", "platform": "android", "appVersion": "1.0.0"}'
```

Response:
```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGci...",
    "tokenType": "Bearer",
    "expiresIn": 86400000,
    "deviceId": "android-unique-device-id-here"
  }
}
```

---

### Scan URL

**POST** `/api/v1/scan` — Analyze URL for threats (uses Sequential Priority Scanning)

```bash
curl -X POST http://localhost:8080/api/v1/scan \
  -H "Authorization: Bearer <YOUR_JWT>" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

Response:
```json
{
  "success": true,
  "data": {
    "url": "https://example.com",
    "riskScore": 82,
    "status": "DANGEROUS",
    "sources": {
      "googleSafeBrowsing": {
        "flagged": true,
        "threatType": "MALWARE"
      },
      "virusTotal": {
        "malicious": 12,
        "suspicious": 4,
        "harmless": 54,
        "totalEngines": 70
      },
      "abuseIpDb": {
        "confidenceScore": 88,
        "countryCode": "RU",
        "isTor": false
      },
      "securitySnacksFlagged": true
    },
    "scanTimeMs": 142,
    "isCached": false
  }
}
```

**Risk Status:**
| Score | Status | Description |
|-------|--------|-------------|
| 0–29 | `SAFE` ✅ | URL is safe to navigate |
| 30–59 | `SUSPICIOUS` ⚠️ | URL shows moderate risk factors |
| 60–100 | `DANGEROUS` 🚫 | URL is a confirmed threat |
| N/A | `UNKNOWN` ❓ | Active scan failure (Fail-Closed) |

---

### Threat Intelligence & Stats

**GET** `/api/v1/threats/stats` — Detailed analytics on local threats & files ingested.

**GET** `/api/v1/threats/search?query=phish` — Full-text and wildcard local database search.

**GET** `/api/v1/threats/top-domains?page=0&pageSize=20` — Domains with the highest malicious counts & worst reputations.

---

## 🔒 Production-Grade Security Features

| Feature | Implementation Details |
|---------|------------------------|
| **Device-Based JWT** | Custom `JwtAuthenticationFilter` with fast database validation. |
| **SSRF Protection** | `@ValidUrl` request validation rejecting private, loopback, and local IP addresses. |
| **Atomic Rate Limiter** | Redis-based `RateLimitingFilter` using `INCR` + `TTL` atomic checks to prevent infinite lockouts on network drops. |
| **Punycode / Normalization** | `CanonicalUrlService` handles domain homograph attacks, strips tracking parameters, and lowercases domain paths. |
| **Offline Ingestion Shield** | Ingests OSINT feeds into a local **Guava Bloom Filter** for instantaneous lookup under 2ms. |
| **Robust API Statuses** | `ThreatIntelStatus` maps `SUCCESS`, `UNKNOWN`, `TIMEOUT`, `RATE_LIMITED`, `FAILED` for clear upstream handling. |
| **Zero-Day 404 Mapping** | VirusTotal `404` errors are mapped to `UNKNOWN` instead of `SAFE` (preventing false negative zero-day bypasses). |
| **Fail-Closed Strategy** | If all upstream APIs fail, the scan returns `UNKNOWN` to warn the client rather than assuming safety. |
| **Non-blocking Controllers** | Replaced `runBlocking` with Spring Web MVC `suspend fun` controller methods to free Tomcat threads during remote I/O. |
| **Persistence Isolation** | `ScanRepositoryAdapter` encapsulates blocking JDBC/JPA operations on `Dispatchers.IO` to keep business logic thread-safe. |
| **Negative Caching** | Redis variable TTLs (`DANGEROUS` 30 days, `SAFE` 15 mins, `UNKNOWN` 3 mins) to avoid overloading remote APIs. |
| **Structured Concurrency** | `BackgroundJobScope` manages asynchronous ingestion tasks via a dedicated `SupervisorJob` and handles server shutdown events. |

---

## 🏗️ Priority-Based Sequential Scan Pipeline

Instead of launching parallel HTTP requests that exhaust API quotas (especially VirusTotal's strict limits), the backend evaluates threat actors sequentially using a priority pipeline:

```
                  ┌──────────────────────┐
                  │      Scan Request    │
                  └──────────┬───────────┘
                             │
                             ▼
               ┌───────────────────────────┐
               │    Offline Bloom Shield   │──[HIT]──┐
               └─────────────┬─────────────┘         │
                             │ [MISS]                │
                             ▼                       ▼
               ┌───────────────────────────┐   ┌─────────────┐
               │   Google Safe Browsing    │   │ Local Cache │
               └─────────────┬─────────────┘   └─────────────┘
                             │
                     [Flagged Malicious?]
                     ├─── Yes ───► [FAST RETURN DANGEROUS] (Skip external API calls)
                     └─── No / Err
                           │
                           ▼
               ┌───────────────────────────┐
               │    AbuseIPDB Reputation   │
               └─────────────┬─────────────┘
                             │
                    [Escalation Triggers?]
                    ├─── Yes ───► [VirusTotal Deep Scan]
                    └─── No  ───► [Assemble Local Verdict]
```

### Escalation Triggers for VirusTotal Deep Scan
VirusTotal is called **only if** safety cannot be verified through cheaper engines:
1. Google Safe Browsing returned `UNKNOWN` or an active failure (timeout, rate limit).
2. The domain reputation is unknown or IP abuse confidence is low/unavailable.
3. Local heuristic analysis raises high-risk findings (e.g., suspicious Punycode patterns, fake login keywords).
4. The intermediate calculated risk score is in the `SUSPICIOUS` range.

---

## 🧪 Running Tests & Compiling

```bash
# Compile and check Kotlin configuration
./gradlew compileKotlin

# Run unit tests (including CanonicalUrlService and ScanEngineService sequential pipeline)
./gradlew test

# Build executable production JAR
./gradlew bootJar
```
