package com.esg.project.service;

import com.esg.project.model.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

public class JwtServiceTest {

    private JwtService jwtService;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService();
        ReflectionTestUtils.setField(jwtService, "secret", "mysecretkeyforjwtatleast256bitslong!!!!!");
        ReflectionTestUtils.setField(jwtService, "expiration", 3600000L);
    }

    @Test
    void generateAndValidateToken() {
        User user = new User();
        user.setEmployeeId("E123");
        user.setRole("ADMIN");

        String token = jwtService.generateToken(user);
        assertThat(token).isNotNull();
        
        assertThat(jwtService.isTokenValid(token)).isTrue();
        assertThat(jwtService.extractEmployeeId(token)).isEqualTo("E123");
    }

    @Test
    void invalidToken_ReturnsFalse() {
        assertThat(jwtService.isTokenValid("invalid-token")).isFalse();
    }
}
