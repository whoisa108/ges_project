package com.esg.project.controller;

import com.esg.project.model.User;
import com.esg.project.service.AdminService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
public class AdminControllerTest {

    private MockMvc mockMvc;

    @Mock
    private AdminService adminService;

    @InjectMocks
    private AdminController adminController;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(adminController).build();
        
        User adminUser = new User();
        adminUser.setRole("ADMIN");
        adminUser.setEmployeeId("admin-01");

        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn(adminUser);
        
        SecurityContext securityContext = mock(SecurityContext.class);
        when(securityContext.getAuthentication()).thenReturn(auth);
        SecurityContextHolder.setContext(securityContext);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void getAllUsers_ReturnsOk() throws Exception {
        when(adminService.getAllUsers()).thenReturn(Arrays.asList(new User()));
        mockMvc.perform(get("/api/admin/users"))
                .andExpect(status().isOk());
    }

    @Test
    void deleteUser_ReturnsOk() throws Exception {
        mockMvc.perform(delete("/api/admin/users/123"))
                .andExpect(status().isOk());
    }

    @Test
    void updateUser_ReturnsOk() throws Exception {
        Map<String, String> body = new HashMap<>();
        body.put("department", "AAID");
        body.put("role", "USER");
        
        when(adminService.updateUser(anyString(), anyString(), anyString())).thenReturn(Optional.of(new User()));

        mockMvc.perform(put("/api/admin/users/123")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"department\":\"AAID\", \"role\":\"USER\"}"))
                .andExpect(status().isOk());
    }

    @Test
    void setDeadline_ReturnsOk() throws Exception {
        mockMvc.perform(post("/api/admin/deadline")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"deadline\":\"2026-12-31\"}"))
                .andExpect(status().isOk());
    }

    @Test
    void getAuditLogs_ReturnsOk() throws Exception {
        when(adminService.getAuditLogs()).thenReturn(Arrays.asList());
        mockMvc.perform(get("/api/admin/audit-logs"))
                .andExpect(status().isOk());
    }
}
