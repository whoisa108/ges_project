package com.esg.project.controller;

import com.esg.project.model.User;
import com.esg.project.service.AuthService;
import com.esg.project.dto.LoginRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody User user) {
        if (authService.findByEmployeeId(user.getEmployeeId()).isPresent()) {
            return ResponseEntity.badRequest().body("Employee ID already exists");
        }
        authService.register(user);
        return ResponseEntity.ok("User registered successfully");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest, HttpServletResponse response) {
        return authService.login(loginRequest.getEmployeeId(), loginRequest.getPassword())
                .<ResponseEntity<?>>map(userData -> {
                    String token = (String) userData.get("token");
                    Cookie cookie = new Cookie("esg_token", token);
                    cookie.setHttpOnly(true);
                    cookie.setSecure(false); // Set to true in production with HTTPS
                    cookie.setPath("/");
                    cookie.setMaxAge(24 * 60 * 60); // 1 day
                    response.addCookie(cookie);

                    userData.remove("token");
                    return ResponseEntity.ok(userData);
                })
                .orElse(ResponseEntity.status(401).body("Invalid credentials"));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletResponse response) {
        Cookie cookie = new Cookie("esg_token", null);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
        return ResponseEntity.ok("Logged out successfully");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> body) {
        String newPassword = body.get("password");
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        authService.updatePassword(user, newPassword);
        return ResponseEntity.ok("Password updated");
    }
}
