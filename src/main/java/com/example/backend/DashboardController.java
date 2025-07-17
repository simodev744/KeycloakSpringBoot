package com.example.backend;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.http.HttpRequest;

@RestController
@RequestMapping("/api/dashboard")
public class DashboardController {

    @GetMapping("/etudiant")
    @PreAuthorize("hasRole('ETUDIANT')")
    public String getEtudiantDashboard() {
        return "Welcome to the Etudiant Dashboard";
    }

    @GetMapping("/formateur")
    @PreAuthorize("FORMATEUR")
    public String getFormateurDashboard() {
        return "Welcome to the Formateur Dashboard";
    }

    @GetMapping("/administrateur")
    @PreAuthorize("hasRole('ADMINISTRATEUR')")
    public String getAdministrateurDashboard() {
        return "Welcome to the Administrateur Dashboard";
                                               }

    @GetMapping("/test/test")
    public String test(HttpServletRequest http) {
        return "Welcome to test "+http.getHeader("AUTHORIZATION");
    }

    @GetMapping("/test/auth")
    public Authentication auth(Authentication auth) {
        return auth;
    }
}
