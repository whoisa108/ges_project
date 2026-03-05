package com.esg.project.service;

import com.esg.project.model.User;
import com.esg.project.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private JwtService jwtService;

    @Mock
    private BCryptPasswordEncoder encoder;

    @InjectMocks
    private AuthService authService;

    private User user;

    @BeforeEach
    void setUp() {
        user = new User();
        user.setEmployeeId("123");
        user.setPassword("rawPassword");
        user.setRole("USER");
    }

    @Test
    void register_EncodesPasswordAndSaves() {
        when(encoder.encode("rawPassword")).thenReturn("encodedPassword");
        authService.register(user);
        assertThat(user.getPassword()).isEqualTo("encodedPassword");
        assertThat(user.getRole()).isEqualTo("PROPOSER");
        verify(userRepository).save(user);
    }

    @Test
    void login_Success_ReturnsTokenInfo() {
        user.setPassword("encodedPassword");
        when(userRepository.findByEmployeeId("123")).thenReturn(Optional.of(user));
        when(encoder.matches("rawPassword", "encodedPassword")).thenReturn(true);
        when(jwtService.generateToken(user)).thenReturn("mockToken");

        Optional<Map<String, Object>> result = authService.login("123", "rawPassword");

        assertThat(result).isPresent();
        assertThat(result.get().get("token")).isEqualTo("mockToken");
        assertThat(result.get().get("employeeId")).isEqualTo("123");
    }

    @Test
    void login_WrongPassword_ReturnsEmpty() {
        user.setPassword("encodedPassword");
        when(userRepository.findByEmployeeId("123")).thenReturn(Optional.of(user));
        when(encoder.matches("wrong", "encodedPassword")).thenReturn(false);

        Optional<Map<String, Object>> result = authService.login("123", "wrong");

        assertThat(result).isEmpty();
    }

    @Test
    void updatePassword_EncodesAndSaves() {
        when(encoder.encode("newPass")).thenReturn("newEncoded");
        authService.updatePassword(user, "newPass");
        assertThat(user.getPassword()).isEqualTo("newEncoded");
        assertThat(user.isNeedsPasswordReset()).isFalse();
        verify(userRepository).save(user);
    }
}
