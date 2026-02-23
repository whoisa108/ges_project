package com.example.demo;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.minio.BucketExistsArgs;
import io.minio.MakeBucketArgs;
import io.minio.MinioClient;
import io.minio.PutObjectArgs;
import jakarta.annotation.PostConstruct;
import org.springframework.http.ResponseEntity;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.multipart.MultipartFile;

import java.security.Key;
import java.time.LocalDateTime;
import java.util.*;

/**
 * ESG Idea Competition - Single Page Backend Implementation
 * This file contains all core models, repositories, security configs, and common utilities.
 * Manual Getters/Setters added for robust compilation (Lombok-free).
 */

@SpringBootApplication
public class DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }

    @Bean
    public org.springframework.boot.CommandLineRunner initAdmin(UserRepository repo, BCryptPasswordEncoder encoder) {
        return args -> {
            if (repo.findByEmployeeId("admin").isEmpty()) {
                User admin = new User();
                admin.setEmployeeId("admin");
                admin.setName("Administrator");
                admin.setPassword(encoder.encode("admin123"));
                admin.setRole("ADMIN");
                admin.setDepartment("SYSTEM");
                admin.setNeedsPasswordReset(true); // 強制重設
                repo.save(admin);
            }
        };
    }

    // InitDeadline
    @Bean
    public org.springframework.boot.CommandLineRunner initDeadline(SettingRepository repo) {
        return args -> {
            if (repo.findByKey("deadline").isEmpty()) {
                Setting setting = new Setting();
                setting.setKey("deadline");
                setting.setValue(LocalDateTime.of(2026, 3, 17, 23, 59, 59).toString());
                repo.save(setting);
            }
        };
    }

}

// --- MODELS ---

@Document(collection = "users")
class User {
    @Id private String id;
    private String employeeId;
    private String name;
    private String department;
    private String password;
    private String role;
    private boolean needsPasswordReset;

    // Getters and Setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getEmployeeId() { return employeeId; }
    public void setEmployeeId(String employeeId) { this.employeeId = employeeId; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getDepartment() { return department; }
    public void setDepartment(String department) { this.department = department; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }
    public boolean isNeedsPasswordReset() { return needsPasswordReset; }
    public void setNeedsPasswordReset(boolean needsPasswordReset) { this.needsPasswordReset = needsPasswordReset; }
}

@Document(collection = "proposals")
class Proposal {
    @Id private String id;
    private String creatorId;
    private String creatorName;
    private String category;
    private String direction;
    private String title;
    private String summary;
    private String fileName;
    private List<TeamMember> teamMembers;
    private LocalDateTime createdAt;

    // Getters and Setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getCreatorId() { return creatorId; }
    public void setCreatorId(String creatorId) { this.creatorId = creatorId; }
    public String getCreatorName() { return creatorName; }
    public void setCreatorName(String creatorName) { this.creatorName = creatorName; }
    public String getCategory() { return category; }
    public void setCategory(String category) { this.category = category; }
    public String getDirection() { return direction; }
    public void setDirection(String direction) { this.direction = direction; }
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    public String getSummary() { return summary; }
    public void setSummary(String summary) { this.summary = summary; }
    public String getFileName() { return fileName; }
    public void setFileName(String fileName) { this.fileName = fileName; }
    public List<TeamMember> getTeamMembers() { return teamMembers; }
    public void setTeamMembers(List<TeamMember> teamMembers) { this.teamMembers = teamMembers; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
}

class TeamMember {
    private String name;
    private String employeeId;
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getEmployeeId() { return employeeId; }
    public void setEmployeeId(String employeeId) { this.employeeId = employeeId; }
}

@Document(collection = "audit_logs")
class AuditLog {
    @Id private String id;
    private String action;
    private String performedBy;
    private String details;
    private LocalDateTime timestamp;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getAction() { return action; }
    public void setAction(String action) { this.action = action; }
    public String getPerformedBy() { return performedBy; }
    public void setPerformedBy(String performedBy) { this.performedBy = performedBy; }
    public String getDetails() { return details; }
    public void setDetails(String details) { this.details = details; }
    public LocalDateTime getTimestamp() { return timestamp; }
    public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }
}

@Document(collection = "settings")
class Setting {
    @Id private String id;
    private String key;
    private String value;

    public Setting() {}
    public Setting(String id, String key, String value) {
        this.id = id; this.key = key; this.value = value;
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getKey() { return key; }
    public void setKey(String key) { this.key = key; }
    public String getValue() { return value; }
    public void setValue(String value) { this.value = value; }
}

// --- REPOSITORIES ---

@Repository interface UserRepository extends MongoRepository<User, String> {
    Optional<User> findByEmployeeId(String employeeId);
}

@Repository interface ProposalRepository extends MongoRepository<Proposal, String> {
    List<Proposal> findByCreatorId(String creatorId);
    Optional<Proposal> findByCreatorIdAndTitle(String creatorId, String title);
}

@Repository interface AuditLogRepository extends MongoRepository<AuditLog, String> {}
@Repository interface SettingRepository extends MongoRepository<Setting, String> {
    Optional<Setting> findByKey(String key);
}

// --- SECURITY & JWT ---

@Service
class JwtService {
    @Value("${jwt.secret}") private String secret;
    @Value("${jwt.expiration}") private long expiration;

    private Key getSigningKey() { return Keys.hmacShaKeyFor(secret.getBytes()); }

    public String generateToken(User user) {
        return Jwts.builder()
                .setSubject(user.getEmployeeId())
                .claim("role", user.getRole())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String extractEmployeeId(String token) {
        return Jwts.parserBuilder().setSigningKey(getSigningKey()).build()
                .parseClaimsJws(token).getBody().getSubject();
    }

    public boolean isTokenValid(String token) {
        try { Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(token); return true; }
        catch (Exception e) { return false; }
    }
}

@Component
class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserRepository userRepository;

    public JwtAuthenticationFilter(JwtService jwtService, UserRepository userRepository) {
        this.jwtService = jwtService;
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(jakarta.servlet.http.HttpServletRequest request, 
                                    jakarta.servlet.http.HttpServletResponse response, 
                                    jakarta.servlet.FilterChain filterChain) throws jakarta.servlet.ServletException, java.io.IOException {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String jwt = authHeader.substring(7);
            if (jwtService.isTokenValid(jwt)) {
                String empId = jwtService.extractEmployeeId(jwt);
                userRepository.findByEmployeeId(empId).ifPresent(user -> {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(user, null, new ArrayList<>());
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                });
            }
        }
        filterChain.doFilter(request, response);
    }
}

@Configuration
@EnableWebSecurity
class SecurityConfig {
    private final JwtAuthenticationFilter jwtFilter;
    public SecurityConfig(JwtAuthenticationFilter jwtFilter) { this.jwtFilter = jwtFilter; }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/**").permitAll()
                .anyRequest().authenticated()
            )
            .addFilterBefore(jwtFilter, org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(); }
}

// --- MINIO SERVICE ---

@Service
class StorageService {
    @Value("${minio.url}") private String url;
    @Value("${minio.access-key}") private String accessKey;
    @Value("${minio.secret-key}") private String secretKey;
    @Value("${minio.bucket-name}") private String bucket;

    private MinioClient minioClient;

    @PostConstruct
    public void init() {
        minioClient = MinioClient.builder().endpoint(url).credentials(accessKey, secretKey).build();
        try {
            if (!minioClient.bucketExists(BucketExistsArgs.builder().bucket(bucket).build())) {
                minioClient.makeBucket(MakeBucketArgs.builder().bucket(bucket).build());
            }
        } catch (Exception e) { System.err.println("MinIO Init Delayed: " + e.getMessage()); }
    }

    public String uploadFile(MultipartFile file, String fileName) {
        try {
            minioClient.putObject(PutObjectArgs.builder()
                .bucket(bucket).object(fileName)
                .stream(file.getInputStream(), file.getSize(), -1)
                .contentType(file.getContentType())
                .build());
            return fileName;
        } catch (Exception e) { throw new RuntimeException("Upload failed", e); }
    }

    public io.minio.GetObjectResponse getFile(String fileName) {
        try {
            return minioClient.getObject(io.minio.GetObjectArgs.builder()
                .bucket(bucket).object(fileName).build());
        } catch (Exception e) { throw new RuntimeException("Download failed", e); }
    }

    public void deleteFile(String fileName) {
        try {
            minioClient.removeObject(io.minio.RemoveObjectArgs.builder()
                .bucket(bucket).object(fileName).build());
        } catch (Exception e) { System.err.println("File deletion failed: " + e.getMessage()); }
    }
}

// --- AUDIT LOG ASPECT ---

@Aspect
@Component
class AuditLogAspect {
    private final AuditLogRepository auditLogRepository;
    public AuditLogAspect(AuditLogRepository auditLogRepository) { this.auditLogRepository = auditLogRepository; }

    @AfterReturning(pointcut = "within(com.example.demo..*) && (@annotation(org.springframework.web.bind.annotation.PostMapping) || @annotation(org.springframework.web.bind.annotation.PutMapping) || @annotation(org.springframework.web.bind.annotation.DeleteMapping))", returning = "result")
    public void logAction(JoinPoint joinPoint, Object result) {
        String methodName = joinPoint.getSignature().getName();
        String user = "Anonymous";
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            if (principal instanceof User) user = ((User) principal).getEmployeeId();
        }
        
        AuditLog log = new AuditLog();
        log.setAction(methodName);
        log.setPerformedBy(user);
        log.setDetails("Called " + joinPoint.getSignature().toShortString());
        log.setTimestamp(LocalDateTime.now());
        auditLogRepository.save(log);
    }
}

/**
 * ESG Idea Competition - API Controllers
 * Consolidates Auth, Proposal, and Admin APIs into one file.
 * Manual adjustments for robust compilation without Lombok.
 */

@RestController
@RequestMapping("/api")
class ApiController {
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
            resp.put("needsPasswordReset", u.isNeedsPasswordReset());
            return ResponseEntity.ok(resp);
        }
        return ResponseEntity.status(401).body("Invalid credentials");
    }

    @PostMapping("/auth/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> body) {
        String newPassword = body.get("password");
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        
        user.setPassword(encoder.encode(newPassword));
        user.setNeedsPasswordReset(false);
        userRepository.save(user);
        
        return ResponseEntity.ok("Password updated");
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
            @RequestParam(value = "teamMembers", required = false) String teamMembersJson,
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

        if (teamMembersJson != null && !teamMembersJson.isEmpty()) {
            try {
                List<TeamMember> teamMembers = new ObjectMapper().readValue(teamMembersJson, new TypeReference<List<TeamMember>>() {});
                p.setTeamMembers(teamMembers);
            } catch (Exception e) {
                return ResponseEntity.badRequest().body("Invalid team members format: " + e.getMessage());
            }
        }
        
        proposalRepository.save(p);
        return ResponseEntity.ok(p);
    }

    @DeleteMapping("/proposals/{id}")
    public ResponseEntity<?> deleteProposal(@PathVariable String id) {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        Optional<Proposal> p = proposalRepository.findById(id);
        
        if (p.isPresent()) {
            if ("ADMIN".equals(user.getRole()) || p.get().getCreatorId().equals(user.getEmployeeId())) {
                // Delete file from MinIO first
                if (p.get().getFileName() != null) {
                    storageService.deleteFile(p.get().getFileName());
                }
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

    @PostMapping("/admin/set-password")
    public ResponseEntity<?> setPassword(@RequestBody Map<String, String> body) {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (!"ADMIN".equals(user.getRole())) return ResponseEntity.status(403).build();
        
        Optional<User> userOpt = userRepository.findByEmployeeId(body.get("employeeId"));
        if (userOpt.isPresent()) {
            User u = userOpt.get();
            u.setPassword(encoder.encode(body.get("password")));
            userRepository.save(u);
            return ResponseEntity.ok("Password updated");
        }
        return ResponseEntity.notFound().build();
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
