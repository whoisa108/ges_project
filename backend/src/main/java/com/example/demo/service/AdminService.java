package com.example.demo.service;

import com.example.demo.model.User;
import com.example.demo.model.AuditLog;
import com.example.demo.model.Setting;
import com.example.demo.repository.UserRepository;
import com.example.demo.repository.AuditLogRepository;
import com.example.demo.repository.SettingRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class AdminService {
    private final UserRepository userRepository;
    private final AuditLogRepository auditLogRepository;
    private final SettingRepository settingRepository;
    private final BCryptPasswordEncoder encoder;

    public AdminService(UserRepository userRepository, AuditLogRepository auditLogRepository, 
                        SettingRepository settingRepository, BCryptPasswordEncoder encoder) {
        this.userRepository = userRepository;
        this.auditLogRepository = auditLogRepository;
        this.settingRepository = settingRepository;
        this.encoder = encoder;
    }

    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    public void deleteUser(String id) {
        userRepository.deleteById(id);
    }

    public Optional<User> updateUser(String id, String department, String role) {
        return userRepository.findById(id).map(u -> {
            if (department != null) u.setDepartment(department);
            if (role != null) u.setRole(role);
            return userRepository.save(u);
        });
    }

    public Optional<User> setPassword(String employeeId, String password) {
        return userRepository.findByEmployeeId(employeeId).map(u -> {
            u.setPassword(encoder.encode(password));
            return userRepository.save(u);
        });
    }

    public void setDeadline(String deadline) {
        Setting s = settingRepository.findByKey("deadline").orElse(new Setting(null, "deadline", null));
        s.setValue(deadline);
        settingRepository.save(s);
    }

    public Setting getDeadline() {
        return settingRepository.findByKey("deadline").orElse(new Setting(null, "deadline", "Not Set"));
    }

    public List<AuditLog> getAuditLogs() {
        return auditLogRepository.findAll();
    }
}
