package com.esg.project.service;

import com.esg.project.model.User;
import com.esg.project.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Service
public class AuthService {
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final BCryptPasswordEncoder encoder;

    public AuthService(UserRepository userRepository, JwtService jwtService, BCryptPasswordEncoder encoder) {
        this.userRepository = userRepository;
        this.jwtService = jwtService;
        this.encoder = encoder;
    }

    public void register(User user) {
        user.setPassword(encoder.encode(user.getPassword()));
        user.setRole("PROPOSER");
        userRepository.save(user);
    }

    public Optional<User> findByEmployeeId(String employeeId) {
        return userRepository.findByEmployeeId(employeeId);
    }

    public Optional<Map<String, Object>> login(String employeeId, String password) {
        return userRepository.findByEmployeeId(employeeId)
                .filter(u -> encoder.matches(password, u.getPassword()))
                .map(u -> {
                    String token = jwtService.generateToken(u);
                    Map<String, Object> resp = new HashMap<>();
                    resp.put("token", token);
                    resp.put("role", u.getRole());
                    resp.put("name", u.getName());
                    resp.put("employeeId", u.getEmployeeId());
                    resp.put("needsPasswordReset", u.isNeedsPasswordReset());
                    return resp;
                });
    }

    public void updatePassword(User user, String newPassword) {
        user.setPassword(encoder.encode(newPassword));
        user.setNeedsPasswordReset(false);
        userRepository.save(user);
    }
}
