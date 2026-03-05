package com.esg.project.service;

import com.esg.project.model.User;
import com.esg.project.model.Setting;
import com.esg.project.repository.UserRepository;
import com.esg.project.repository.AuditLogRepository;
import com.esg.project.repository.SettingRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class AdminServiceTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private AuditLogRepository auditLogRepository;
    @Mock
    private SettingRepository settingRepository;
    @Mock
    private BCryptPasswordEncoder encoder;

    @InjectMocks
    private AdminService adminService;

    @Test
    void updateUser_ChangesRoleAndDept() {
        User u = new User();
        when(userRepository.findById("id")).thenReturn(Optional.of(u));
        when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArguments()[0]);

        Optional<User> result = adminService.updateUser("id", "HR", "ADMIN");

        assertThat(result).isPresent();
        assertThat(result.get().getDepartment()).isEqualTo("HR");
        assertThat(result.get().getRole()).isEqualTo("ADMIN");
    }

    @Test
    void setDeadline_CreatesNewIfMissing() {
        when(settingRepository.findByKey("deadline")).thenReturn(Optional.empty());
        adminService.setDeadline("2026-01-01T00:00:00");
        verify(settingRepository).save(argThat(s -> s.getValue().equals("2026-01-01T00:00:00")));
    }

    @Test
    void getDeadline_ReturnsDefaultIfMissing() {
        when(settingRepository.findByKey("deadline")).thenReturn(Optional.empty());
        Setting result = adminService.getDeadline();
        assertThat(result.getValue()).isEqualTo("Not Set");
    }
}
