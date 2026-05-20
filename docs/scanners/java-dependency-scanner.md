# Java Dependency Scanner

**Type:** SAST | **Severity:** Critical–Medium | **Category:** Dependency Vulnerability

## What It Does

Scans Java/Kotlin dependency files for known vulnerable libraries:

- **pom.xml** (Maven) — parses `<dependency>` blocks with groupId, artifactId, version
- **build.gradle / build.gradle.kts** (Gradle) — parses `implementation`, `api`, `compile` declarations
- Checks 12 common packages against a built-in CVE database
- Skips property-referenced versions (`${version.property}`)

Known vulnerability database includes: Log4j (Log4Shell), Apache Struts, Spring Boot, Spring Security, Jackson Databind, JJWT, Commons Text (Text4Shell), Commons IO, Guava, Tomcat, MySQL Connector.

## Why It Matters

Java dependency vulnerabilities have caused some of the largest breaches in history:

- **Log4Shell (2021)** — CVE-2021-44228 in Log4j allowed RCE via log messages. Affected every major tech company.
- **Apache Struts (2017)** — CVE-2017-5638 caused the Equifax breach (147 million records)
- **Text4Shell (2022)** — CVE-2022-42889 in Commons Text allowed RCE via string interpolation

## Real-World Breaches

**Equifax (2017)** — 147 million records stolen because of an unpatched Apache Struts dependency. The patch had been available for two months. Equifax paid $700 million in settlements.

**Log4Shell (2021)** — Affected hundreds of thousands of applications including Apple, Amazon, Cloudflare, and Steam. One of the most impactful vulnerabilities ever discovered.

## How to Fix

```xml
<!-- Maven: update to safe versions -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.21.0</version> <!-- Fixed -->
</dependency>
```

```groovy
// Gradle: update to safe versions
implementation 'org.apache.logging.log4j:log4j-core:2.21.0'
```

Use OWASP Dependency-Check or Snyk for automated scanning in CI.
