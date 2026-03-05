package com.esg.project.controller;

import com.esg.project.model.User;
import com.esg.project.model.Proposal;
import com.esg.project.service.ProposalService;
import com.esg.project.service.StorageService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.ArrayList;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
public class ProposalControllerTest {

    private MockMvc mockMvc;

    @Mock
    private ProposalService proposalService;
    @Mock
    private StorageService storageService;

    @InjectMocks
    private ProposalController proposalController;

    private User testUser;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(proposalController).build();

        testUser = new User();
        testUser.setRole("USER");
        testUser.setEmployeeId("user-123");

        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn(testUser);

        SecurityContext securityContext = mock(SecurityContext.class);
        when(securityContext.getAuthentication()).thenReturn(auth);
        SecurityContextHolder.setContext(securityContext);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void getProposals_ReturnsOk() throws Exception {
        when(proposalService.getProposals(any(User.class))).thenReturn(new ArrayList<>());
        mockMvc.perform(get("/api/proposals"))
                .andExpect(status().isOk());
    }

    @Test
    void createProposal_Success() throws Exception {
        MockMultipartFile file = new MockMultipartFile("file", "test.pdf", "application/pdf", "content".getBytes());
        when(proposalService.isDuplicateTitle(anyString(), anyString())).thenReturn(false);
        when(proposalService.isDeadlinePassed()).thenReturn(false);
        when(proposalService.createProposal(any(), anyString(), anyString(), anyString(), anyString(), any(), any()))
                .thenReturn(new Proposal());

        mockMvc.perform(multipart("/api/proposals")
                .file(file)
                .param("title", "Title")
                .param("category", "Cat")
                .param("direction", "Dir")
                .param("summary", "Sum"))
                .andDo(org.springframework.test.web.servlet.result.MockMvcResultHandlers.print())
                .andExpect(status().isOk());
    }

    @Test
    void deleteProposal_Success() throws Exception {
        Proposal p = new Proposal();
        p.setCreatorId("user-123");
        when(proposalService.findById("1")).thenReturn(Optional.of(p));

        mockMvc.perform(delete("/api/proposals/1"))
                .andExpect(status().isOk());
    }

    @Test
    void updateProposal_Success() throws Exception {
        Proposal p = new Proposal();
        p.setCreatorId("user-123");
        when(proposalService.findById("1")).thenReturn(Optional.of(p));
        when(proposalService.isDeadlinePassed()).thenReturn(false);

        mockMvc.perform(post("/api/proposals/1")
                .param("title", "New Title")
                .param("category", "Cat")
                .param("direction", "Dir")
                .param("summary", "Sum"))
                .andExpect(status().isOk());
    }

    @Test
    void downloadFile_Success() throws Exception {
        Proposal p = new Proposal();
        p.setFileName("test.pdf");
        p.setCreatorId("user-123");
        when(proposalService.findById("1")).thenReturn(Optional.of(p));

        io.minio.GetObjectResponse mockResponse = mock(io.minio.GetObjectResponse.class);
        when(storageService.getFile("test.pdf")).thenReturn(mockResponse);
        when(mockResponse.headers()).thenReturn(okhttp3.Headers.of("Content-Type", "application/pdf"));

        mockMvc.perform(get("/api/proposals/1/download"))
                .andExpect(status().isOk());
    }
}
