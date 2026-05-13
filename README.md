# 🔐 Mobile Security Scanner — Backend

> **Production-ready Kotlin/Spring Boot backend** for intelligent URL threat analysis.
> Integrates Google Safe Browsing, VirusTotal, AbuseIPDB, and SecuritySnacks Feed
> with weighted scoring, async parallel scanning, JWT auth, and full Docker deployment support.

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
│  │ /auth/register│  │  /scan       │  │ /report, /threats  │   │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬─────────┘   │
│         │                 │                       │             │
│  ┌──────▼─────────────────▼───────────────────────▼─────────┐  │
│  │                  Service Layer                            │  │
│  │  AuthService │ ScanEngineService │ ThreatIntelService    │  │
│  └──────────────────────┬──────────────────────────────────┘  │
│                         │ Parallel Async (Coroutines)          │
│         ┌───────────────┼───────────────┬────────────────┐     │
│         ▼               ▼               ▼                ▼     │
│  ┌─────────────┐ ┌────────────┐ ┌──────────────┐ ┌─────────────┐│
│  │Google Safe  │ │VirusTotal  │ │  AbuseIPDB   │ │ SSL, Snack &││
│  │Browsing     │ │Client      │ │  Client      │ │ Heuristic   ││
│  │(High Weight)│ │(Med Weight)│ │(Low Weight)  │ │ (Local)     ││
│  └─────────────┘ └────────────┘ └──────────────┘ └─────────────┘│
│         │ Circuit Breaker + Retry + Exponential Backoff        │
│  ┌──────▼──────────────────────────────────────────────────┐  │
│  │         Hybrid Weighted Risk Engine                      │  │
│  │  SAFE | SUSPICIOUS | DANGEROUS | UNKNOWN (Fail-Closed)   │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌─────────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │   PostgreSQL    │  │    Redis     │  │   Prometheus +   │  │
│  │  (Persistence)  │  │   (Cache +   │  │     Grafana      │  │
│  │                 │  │ Rate Limit)  │  │  (Monitoring)    │  │
│  └─────────────────┘  └──────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Package Structure (Clean/Hexagonal Architecture)

```
src/main/kotlin/com/security/scanner/
├── MobileSecurityScannerApplication.kt
├── controller/          # REST API controllers (Adapters - Input)
│   ├── AuthController.kt
│   ├── ScanController.kt
│   ├── ConfigController.kt
│   └── ThreatIntelligenceController.kt
├── service/             # Business logic (Application Layer)
│   ├── AuthService.kt
│   ├── ScanEngineService.kt
│   ├── ConfigService.kt
│   ├── ThreatIntelligenceService.kt
│   └── SecuritySnacksIngestionService.kt
├── ssl/                 # SSL/TLS Analysis Module
│   └── SslAnalyzer.kt
├── heuristic/           # Heuristic Detection Engine
│   └── HeuristicAnalyzer.kt
├── domain/              # Domain models and DTOs
│   ├── model/           # JPA Entities
│   │   ├── Device.kt
│   │   ├── ScanResult.kt
│   │   ├── MaliciousUrl.kt
│   │   └── FalseNegativeReport.kt
│   └── dto/             # API Request/Response objects
│       └── Dtos.kt
├── repository/          # Database access (Adapters - Output)
│   ├── DeviceRepository.kt
│   ├── ScanResultRepository.kt
│   ├── MaliciousUrlRepository.kt
│   ├── FalseNegativeReportRepository.kt
│   └── SecuritySnacksRepository.kt
├── external/            # Third-party integrations (Adapters - Output)
│   └── integration/
│       ├── ThreatIntelligencePort.kt  # Port interface
│       ├── GoogleSafeBrowsingClient.kt
│       ├── VirusTotalClient.kt
│       ├── AbuseIpDbClient.kt
│       └── SecuritySnacksClient.kt
├── security/            # Authentication & Security
│   ├── JwtService.kt
│   ├── JwtAuthenticationFilter.kt
│   └── RateLimitingFilter.kt
├── config/              # Spring configuration
│   ├── SecurityConfig.kt
│   ├── SecuritySnacksConfig.kt
│   ├── AppConfig.kt       # Typed properties
│   ├── WebClientConfig.kt
│   └── OpenApiConfig.kt
└── common/              # Shared utilities
    ├── GlobalExceptionHandler.kt
    ├── RequestLoggingFilter.kt
    └── UrlValidator.kt
```

---

## 🚀 Quick Start (Local Development)

### Prerequisites
- Docker & Docker Compose
- JDK 21 (for running without Docker)
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

**POST** `/api/v1/auth/register` — Register device & get JWT

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

**POST** `/api/v1/scan` — Analyze URL for threats

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
    "scanTimeMs": 532,
    "isCached": false
  }
}
```

**Risk Status:**
| Score | Status |
|-------|--------|
| 0–29 | `SAFE` ✅ |
| 30–59 | `SUSPICIOUS` ⚠️ |
| 60–100 | `DANGEROUS` 🚫 |
| N/A | `UNKNOWN` ❓ (API Failures) |

---

### Dynamic Config

**GET** `/api/v1/config`

```json
{
  "weights": { "google": 0.5, "virusTotal": 0.3, "abuseIpDb": 0.2 },
  "thresholds": { "safe": 30, "suspicious": 60 },
  "timeoutMs": 10000,
  "maintenance": false,
  "minimumAppVersion": "1.0.0",
  "featureFlags": {
    "parallelScan": true,
    "fastFailOnDangerous": true,
    "cachingEnabled": true
  },
  "offlineThreatList": [
    "bad-domain.com",
    "phishing-site.net"
  ]
}
```

---

### Report False Negative

**POST** `/api/v1/report`

```bash
curl -X POST http://localhost:8080/api/v1/report \
  -H "Authorization: Bearer <YOUR_JWT>" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://phishing-site.com",
    "originalStatus": "SAFE",
    "originalRiskScore": 10,
    "userDescription": "This site stole my credentials"
  }'
```

---

### Top Threats

**GET** `/api/v1/threats/top?page=0&pageSize=20`

---

## 🔒 Security Features

| Feature | Implementation |
|---------|---------------|
| **Authentication** | Device-based JWT (no username/password) |
| **API Key Protection** | All 3rd-party keys server-side only |
| **Rate Limiting** | Redis-based: 100 req/device/hr, 200 req/IP/hr |
| **URL Validation** | Blocks private IPs, localhost, invalid schemes |
| **SSL Analyzer** | Expired, Revoked, Self-Signed, Weak Cipher detection |
| **Heuristic Engine** | Punycode, Fake Login, URL Shortener, Subdomain abuse |
| **Offline Protection** | Auto-discovery of all SecuritySnacks feeds via GitHub Tree API |
| **Ingestion Pipeline** | Automated Cron + Startup sync with Redis & Postgres caching |
| **Secure Headers** | X-Frame-Options, CSP, HSTS, XSS-Protection |
| **Circuit Breaker** | Resilience4j per each 3rd-party service |
| **Retry + Backoff** | Exponential backoff on failures |
| **HTTPS** | Nginx SSL termination |
| **Input Validation** | Jakarta Bean Validation on all inputs |

---

## 🏗️ Scan Engine Details

### Hybrid Weighted Scoring Engine

```
finalScore = Σ(sourceScore) -> Capped at 100

Primary Drivers:
  SecuritySnacks       : +100 (High Confidence Threat Intel)
  Google Safe Browsing : +80 (Flagged)
  VirusTotal           : +90 (Malicious > 0), +50 (Suspicious > 0)
  AbuseIPDB            : +50 (Confidence > 50%)
  SSL Analysis         : +20 to +70 (Expired, Revoked, Weak Ciphers)
  Heuristic Analysis   : +10 to +40 (Punycode, Keywords, Fake Logins)
  API Failure Penalty  : +15 per failed service (Fail-Closed Policy)
```

### Smart Parallel Scan Flow

```
Request → [Google Safe Browsing] ──→ flagged? ──YES──→ Fast-return DANGEROUS
                                          │
                                         NO
                                          ↓
                              [All 3 sources in parallel]
                                          ↓
                              Weighted score aggregation
                                          ↓
                              SAFE | SUSPICIOUS | DANGEROUS
```

---

## 🐳 Production Deployment (Ubuntu VPS)

```bash
# 1. Clone repo
git clone <repo-url> /opt/security-scanner
cd /opt/security-scanner

# 2. Configure environment
cp .env.example .env
nano .env  # Fill in production values

# 3. Set up SSL (Let's Encrypt recommended)
apt install certbot
certbot certonly --standalone -d yourdomain.com
cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem nginx/ssl/cert.pem
cp /etc/letsencrypt/live/yourdomain.com/privkey.pem nginx/ssl/key.pem

# 4. Start production stack
docker-compose up -d --build

# 5. Monitor
docker-compose logs -f app
```

---

## 🔑 API Keys Setup

| Service | Get Key |
|---------|---------|
| **Google Safe Browsing** | [Google Cloud Console](https://console.cloud.google.com/) → Enable Safe Browsing API |
| **VirusTotal** | [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) |
| **AbuseIPDB** | [abuseipdb.com/account/api](https://www.abuseipdb.com/account/api) |

---

## 📊 Monitoring

| Tool | URL | Credentials |
|------|-----|-------------|
| Swagger UI | `http://localhost:8080/swagger-ui.html` | — |
| Actuator Health | `http://localhost:8080/actuator/health` | — |
| Prometheus | `http://localhost:9090` | — |
| Grafana | `http://localhost:3000` | admin/admin123 |

---

## 🧪 Running Tests

```bash
# Unit tests
./gradlew test

# With coverage
./gradlew test jacocoTestReport

# Build JAR
./gradlew bootJar
```

---

## ⚙️ Environment Variables Reference

See [`.env.example`](.env.example) for all configurable options.

Key required variables:
- `JWT_SECRET` — Min 32 chars random string
- `GOOGLE_SAFE_BROWSING_API_KEY`
- `VIRUS_TOTAL_API_KEY`
- `ABUSE_IPDB_API_KEY`
- `DB_PASSWORD`

---

## 🗓️ Development Roadmap

- [x] **Phase 1**: Auth API, JWT, Mock/Real Scan, Swagger, Docker
- [x] **Phase 2**: Real integrations, weighted scoring, circuit breaker, DB persistence
- [x] **Phase 3**: SSL/TLS analysis, Heuristic engine, Fail-Closed security policy
- [ ] **Phase 4**: Monitoring dashboards, analytics, advanced caching, load testing
