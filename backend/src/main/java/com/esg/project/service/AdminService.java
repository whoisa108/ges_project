package com.esg.project.service;

import com.esg.project.model.User;
import com.esg.project.model.AuditLog;
import com.esg.project.model.Setting;
import com.esg.project.repository.UserRepository;
import com.esg.project.repository.AuditLogRepository;
import com.esg.project.repository.SettingRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AdminService {
    private final UserRepository userRepository;
    private final AuditLogRepository auditLogRepository;
    private final SettingRepository settingRepository;
    private final BCryptPasswordEncoder encoder;

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
