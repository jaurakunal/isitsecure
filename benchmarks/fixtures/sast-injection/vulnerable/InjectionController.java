// Injection benchmark fixture — Java command injection, SSRF, path traversal
// (VULNERABLE). Sources: Spring @RequestParam / HttpServletRequest.
package com.example.vuln;

import java.io.File;
import java.io.FileInputStream;
import java.net.URL;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;

public class InjectionController {
    RestTemplate rest;

    // --- Command injection ---
    public void ping(HttpServletRequest request) throws Exception {
        String host = request.getParameter("host");
        Runtime.getRuntime().exec("ping -c 1 " + host); // EXPECT command-injection
    }

    @GetMapping("/run")
    public void run(@RequestParam String cmd) throws Exception {
        new ProcessBuilder("sh", "-c", cmd).start(); // EXPECT command-injection
    }

    // --- SSRF ---
    @GetMapping("/fetch")
    public void fetch(@RequestParam String url) throws Exception {
        new URL(url).openConnection().getInputStream(); // EXPECT ssrf
    }

    @GetMapping("/proxy")
    public String proxy(@RequestParam String target) {
        return rest.getForObject(target, String.class); // EXPECT ssrf
    }

    // --- Path traversal ---
    @GetMapping("/read")
    public void read(@RequestParam String name) throws Exception {
        new FileInputStream(new File("/data/" + name)); // EXPECT path-traversal
    }
}
