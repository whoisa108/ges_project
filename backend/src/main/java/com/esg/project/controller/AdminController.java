package com.esg.project.controller;

import com.esg.project.model.User;
import com.esg.project.service.AdminService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class AdminController {
    private final AdminService adminService;

    @GetMapping("/admin/users")
    public ResponseEntity<?> getAllUsers() {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (!"ADMIN".equals(user.getRole())) return ResponseEntity.status(403).build();
        return ResponseEntity.ok(adminService.getAllUsers());
    }

    @DeleteMapping("/admin/users/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable String id) {
        User user = (SecurityContextHolder.getContext().getAuthentication() != null) ? 
                     (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal() : null;
        if (user == null || !"ADMIN".equals(user.getRole())) return ResponseEntity.status(403).build();
        adminService.deleteUser(id);
        return ResponseEntity.ok("User deleted");
    }

    @PutMapping("/admin/users/{id}")
    public ResponseEntity<?> updateUser(@PathVariable String id, @RequestBody Map<String, String> body) {
        User admin = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (!"ADMIN".equals(admin.getRole())) return ResponseEntity.status(403).build();

        return adminService.updateUser(id, body.get("department"), body.get("role"))
                .<ResponseEntity<?>>map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/admin/deadline")
    public ResponseEntity<?> setDeadline(@RequestBody Map<String, String> body) {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (!"ADMIN".equals(user.getRole())) return ResponseEntity.status(403).build();
        
        adminService.setDeadline(body.get("deadline"));
        return ResponseEntity.ok("Deadline updated");
    }

    @GetMapping("/deadline")
    public ResponseEntity<?> getDeadline() {
        return ResponseEntity.ok(adminService.getDeadline());
    }

    @GetMapping("/admin/audit-logs")
    public ResponseEntity<?> getAuditLogs() {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (!"ADMIN".equals(user.getRole())) return ResponseEntity.status(403).build();
        return ResponseEntity.ok(adminService.getAuditLogs());
    }
}
