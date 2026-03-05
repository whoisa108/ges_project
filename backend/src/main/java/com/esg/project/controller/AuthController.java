package com.esg.project.controller;

import com.esg.project.model.User;
import com.esg.project.service.AuthService;
import com.esg.project.dto.LoginRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

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
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        return authService.login(loginRequest.getEmployeeId(), loginRequest.getPassword())
                .<ResponseEntity<?>>map(ResponseEntity::ok)
                .orElse(ResponseEntity.status(401).body("Invalid credentials"));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> body) {
        String newPassword = body.get("password");
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        authService.updatePassword(user, newPassword);
        return ResponseEntity.ok("Password updated");
    }
}
