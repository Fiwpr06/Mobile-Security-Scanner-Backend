# =============================================
# Multi-stage Production Dockerfile
# SafeSurf Backend
# =============================================

# Stage 1: Build
FROM gradle:8.7-jdk21-alpine AS builder

WORKDIR /app

# Copy Gradle wrapper and build files first (better cache utilization)
COPY gradle/ gradle/
COPY gradlew .
COPY settings.gradle.kts .
COPY build.gradle.kts .

# Download dependencies (cached layer)
RUN gradle dependencies --no-daemon --quiet || true

# Copy source and build
COPY src/ src/
RUN gradle bootJar --no-daemon -x test

# Stage 2: Production runtime
FROM eclipse-temurin:21-jre-alpine AS runtime

# Security: Run as non-root user
RUN addgroup -S scanner && adduser -S scanner -G scanner

WORKDIR /app

# Install tini for proper signal handling
RUN apk add --no-cache tini curl

# Copy JAR from builder
COPY --from=builder /app/build/libs/*.jar app.jar

# Create logs directory
RUN mkdir -p logs && chown scanner:scanner logs

# Switch to non-root
USER scanner

# JVM tuning for containers
ENV JAVA_OPTS="\
  -XX:+UseContainerSupport \
  -XX:MaxRAMPercentage=75.0 \
  -XX:+UseG1GC \
  -XX:+OptimizeStringConcat \
  -XX:+UseStringDeduplication \
  -Djava.security.egd=file:/dev/./urandom \
  -Dspring.backgroundpreinitializer.ignore=true"

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:8080/actuator/health || exit 1

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["sh", "-c", "java $JAVA_OPTS -jar /app/app.jar"]
