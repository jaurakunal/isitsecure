// Injection benchmark fixture — Kotlin/Spring command injection, SSRF, path
// traversal (VULNERABLE). Constructor sinks use Kotlin's no-`new` form.
package com.example.vuln

import java.io.File
import java.net.URL
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam

class InjectionControllerKt {

    @GetMapping("/run")
    fun run(@RequestParam cmd: String) {
        ProcessBuilder("sh", "-c", cmd).start() // EXPECT command-injection
    }

    @GetMapping("/exec")
    fun exec(@RequestParam host: String) {
        Runtime.getRuntime().exec("ping -c 1 " + host) // EXPECT command-injection
    }

    @GetMapping("/fetch")
    fun fetch(@RequestParam url: String) {
        URL(url).openConnection().getInputStream() // EXPECT ssrf
    }

    @GetMapping("/read")
    fun read(@RequestParam name: String) {
        File("/data/" + name).readText() // EXPECT path-traversal
    }

    // Kotlin single-expression function (no braces) — the param is still a source
    @GetMapping("/download")
    fun download(@RequestParam file: String) =
        File("/data/" + file).readText() // EXPECT path-traversal
}
