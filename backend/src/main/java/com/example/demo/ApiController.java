package com.example.demo;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDateTime;
import java.util.*;

/**
 * ESG Idea Competition - API Controllers
 * Consolidates Auth, Proposal, and Admin APIs into one file.
 * Manual adjustments for robust compilation without Lombok.
 */

@RestController
@RequestMapping("/api")
public class ApiController {
    private final UserRepository userRepository;
    private final ProposalRepository proposalRepository;
    private final SettingRepository settingRepository;
    private final AuditLogRepository auditLogRepository;
    private final JwtService jwtService;
    private final StorageService storageService;
    private final BCryptPasswordEncoder encoder;

    public ApiController(UserRepository userRepository, ProposalRepository proposalRepository, 
                         SettingRepository settingRepository, AuditLogRepository auditLogRepository, 
                         JwtService jwtService, StorageService storageService, BCryptPasswordEncoder encoder) {
        this.userRepository = userRepository;
        this.proposalRepository = proposalRepository;
        this.settingRepository = settingRepository;
        this.auditLogRepository = auditLogRepository;
        this.jwtService = jwtService;
        this.storageService = storageService;
        this.encoder = encoder;
    }

    // --- AUTHENTICATION ---

    @PostMapping("/auth/register")
    public ResponseEntity<?> register(@RequestBody User user) {
        if (userRepository.findByEmployeeId(user.getEmployeeId()).isPresent()) {
            return ResponseEntity.badRequest().body("Employee ID already exists");
        }
        user.setPassword(encoder.encode(user.getPassword()));
        user.setRole("PROPOSER");
        userRepository.save(user);
        return ResponseEntity.ok("User registered successfully");
    }

    @PostMapping("/auth/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> creds) {
        String empId = creds.get("employeeId");
        String password = creds.get("password");
        
        Optional<User> userOpt = userRepository.findByEmployeeId(empId)
                .filter(u -> encoder.matches(password, u.getPassword()));
        
        if (userOpt.isPresent()) {
            User u = userOpt.get();
            String token = jwtService.generateToken(u);
            Map<String, Object> resp = new HashMap<>();
            resp.put("token", token);
            resp.put("role", u.getRole());
            resp.put("name", u.getName());
            resp.put("employeeId", u.getEmployeeId());
            return ResponseEntity.ok(resp);
        }
        return ResponseEntity.status(401).body("Invalid credentials");
    }

    // --- PROPOSALS ---

    @GetMapping("/proposals")
    public List<Proposal> getProposals() {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if ("ADMIN".equals(user.getRole())) return proposalRepository.findAll();
        return proposalRepository.findByCreatorId(user.getEmployeeId());
    }

    @PostMapping("/proposals")
    public ResponseEntity<?> createProposal(
            @RequestParam("title") String title,
            @RequestParam("category") String category,
            @RequestParam("direction") String direction,
            @RequestParam("summary") String summary,
            @RequestParam("file") MultipartFile file) {
        
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        // Duplicate check
        if (proposalRepository.findByCreatorIdAndTitle(user.getEmployeeId(), title).isPresent()) {
            return ResponseEntity.badRequest().body("Duplicate proposal title for this user");
        }

        // Deadline check
        Optional<Setting> deadline = settingRepository.findByKey("deadline");
        if (deadline.isPresent() && LocalDateTime.now().isAfter(LocalDateTime.parse(deadline.get().getValue()))) {
            return ResponseEntity.badRequest().body("Competition deadline has passed");
        }

        // Filename format: Category_Dept_Name_EmpID_Title
        String originalFilename = file.getOriginalFilename();
        String originalExt = originalFilename != null ? originalFilename.substring(originalFilename.lastIndexOf(".")) : ".bin";
        String fileName = category + "_" + user.getDepartment() + "_" + user.getName() + "_" + user.getEmployeeId() + "_" + title + originalExt;

        storageService.uploadFile(file, fileName);

        Proposal p = new Proposal();
        p.setCreatorId(user.getEmployeeId());
        p.setCreatorName(user.getName());
        p.setTitle(title);
        p.setCategory(category);
        p.setDirection(direction);
        p.setSummary(summary);
        p.setFileName(fileName);
        p.setCreatedAt(LocalDateTime.now());
        
        proposalRepository.save(p);
        return ResponseEntity.ok(p);
    }

    @DeleteMapping("/proposals/{id}")
    public ResponseEntity<?> deleteProposal(@PathVariable String id) {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        Optional<Proposal> p = proposalRepository.findById(id);
        
        if (p.isPresent()) {
            if ("ADMIN".equals(user.getRole()) || p.get().getCreatorId().equals(user.getEmployeeId())) {
                proposalRepository.deleteById(id);
                return ResponseEntity.ok("Deleted");
            }
            return ResponseEntity.status(403).body("Forbidden");
        }
        return ResponseEntity.notFound().build();
    }

    // --- ADMIN CONTROLS ---

    @GetMapping("/admin/users")
    public ResponseEntity<?> getAllUsers() {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (!"ADMIN".equals(user.getRole())) return ResponseEntity.status(403).build();
        return ResponseEntity.ok(userRepository.findAll());
    }

    @DeleteMapping("/admin/users/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable String id) {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (!"ADMIN".equals(user.getRole())) return ResponseEntity.status(403).build();
        userRepository.deleteById(id);
        return ResponseEntity.ok("User deleted");
    }

    @PostMapping("/admin/deadline")
    public ResponseEntity<?> setDeadline(@RequestBody Map<String, String> body) {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (!"ADMIN".equals(user.getRole())) return ResponseEntity.status(403).build();
        
        Setting s = settingRepository.findByKey("deadline").orElse(new Setting(null, "deadline", null));
        s.setValue(body.get("deadline")); // Expected format: 2026-12-31T23:59:59
        settingRepository.save(s);
        return ResponseEntity.ok("Deadline updated");
    }

    @GetMapping("/deadline")
    public ResponseEntity<?> getDeadline() {
        return ResponseEntity.ok(settingRepository.findByKey("deadline").orElse(new Setting(null, "deadline", "Not Set")));
    }

    @GetMapping("/admin/audit-logs")
    public ResponseEntity<?> getAuditLogs() {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (!"ADMIN".equals(user.getRole())) return ResponseEntity.status(403).build();
        return ResponseEntity.ok(auditLogRepository.findAll());
    }
}
