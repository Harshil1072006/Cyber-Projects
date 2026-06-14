# =====================================================================
# FinSecure API — Dockerfile
#
# INTENTIONAL VULNERABILITIES (for security assessment demo):
#
# VULN-1: Running as root (USER root)
#   Any container escape gives the attacker root on the host.
#   Secure fix: Add a non-root user and switch to it.
#
# VULN-2: Debug (JDWP) port 5005 exposed
#   Java Debug Wire Protocol exposed — attacker can attach a remote
#   debugger, inspect all live objects, and execute arbitrary code.
#   Secure fix: Never expose JDWP in production images.
#
# VULN-3: Full JDK base image (eclipse-temurin:17-jdk)
#   Ships with javac, jmap, jstack, jconsole — attack surface is huge.
#   Secure fix: Use eclipse-temurin:17-jre or distroless/java17-debian11
#
# VULN-4: No health check defined (easy to detect in container scanning)
# =====================================================================

# VULN-3: JDK image — much larger attack surface than JRE/distroless
FROM eclipse-temurin:17-jdk

# Set working directory
WORKDIR /app

# Copy Maven wrapper + build files
COPY pom.xml .
COPY mvnw .
COPY .mvn .mvn

# Download dependencies (cached layer)
RUN ./mvnw dependency:go-offline -B

# Copy source code
COPY src src

# Build the fat JAR
RUN ./mvnw package -DskipTests -B

# ─── Runtime stage ────────────────────────────────────────────────────────────

# VULN-1: No USER directive — container runs as root (uid=0)
# Secure fix would be:
#   RUN addgroup --system finsecure && adduser --system --ingroup finsecure finsecure
#   USER finsecure

# Application port
EXPOSE 8080

# VULN-2: JDWP debug port exposed — allows remote Java debugger attachment
# -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005
EXPOSE 5005

# Start with JDWP debug agent enabled
# VULN: address=*:5005 binds to ALL interfaces, not just localhost
ENTRYPOINT ["java", \
  "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005", \
  "-jar", "target/finsecure-api-1.0.0.jar"]
