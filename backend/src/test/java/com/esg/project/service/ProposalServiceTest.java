package com.esg.project.service;

import com.esg.project.model.Proposal;
import com.esg.project.model.Setting;
import com.esg.project.model.User;
import com.esg.project.repository.ProposalRepository;
import com.esg.project.repository.SettingRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class ProposalServiceTest {

    @Mock
    private ProposalRepository proposalRepository;

    @Mock
    private SettingRepository settingRepository;

    @Mock
    private StorageService storageService;

    @InjectMocks
    private ProposalService proposalService;

    private User adminUser;
    private User normalUser;

    @BeforeEach
    void setUp() {
        adminUser = new User();
        adminUser.setEmployeeId("admin1");
        adminUser.setRole("ADMIN");

        normalUser = new User();
        normalUser.setEmployeeId("user1");
        normalUser.setRole("USER");
        normalUser.setName("Tester");
        normalUser.setDepartment("IT");
    }

    @Test
    void getProposals_Admin_ReturnsAll() {
        when(proposalRepository.findAll()).thenReturn(Arrays.asList(new Proposal(), new Proposal()));
        List<Proposal> result = proposalService.getProposals(adminUser);
        assertThat(result).hasSize(2);
        verify(proposalRepository).findAll();
    }

    @Test
    void getProposals_User_ReturnsOnlyOwn() {
        when(proposalRepository.findByCreatorId("user1")).thenReturn(Arrays.asList(new Proposal()));
        List<Proposal> result = proposalService.getProposals(normalUser);
        assertThat(result).hasSize(1);
        verify(proposalRepository).findByCreatorId("user1");
    }

    @Test
    void isDeadlinePassed_NoDeadline_ReturnsFalse() {
        when(settingRepository.findByKey("deadline")).thenReturn(Optional.empty());
        assertThat(proposalService.isDeadlinePassed()).isFalse();
    }

    @Test
    void isDeadlinePassed_FutureDeadline_ReturnsFalse() {
        Setting s = new Setting();
        s.setValue(LocalDateTime.now().plusDays(1).toString());
        when(settingRepository.findByKey("deadline")).thenReturn(Optional.of(s));
        assertThat(proposalService.isDeadlinePassed()).isFalse();
    }

    @Test
    void isDeadlinePassed_PastDeadline_ReturnsTrue() {
        Setting s = new Setting();
        s.setValue(LocalDateTime.now().minusDays(1).toString());
        when(settingRepository.findByKey("deadline")).thenReturn(Optional.of(s));
        assertThat(proposalService.isDeadlinePassed()).isTrue();
    }

    @Test
    void createProposal_SavesAndReturns() throws Exception {
        MultipartFile mockFile = mock(MultipartFile.class);
        when(mockFile.getOriginalFilename()).thenReturn("test.pdf");

        Proposal savedProposal = new Proposal();
        savedProposal.setTitle("Test Title");
        when(proposalRepository.save(any(Proposal.class))).thenReturn(savedProposal);

        Proposal result = proposalService.createProposal(normalUser, "Test Title", "Category", "Direction", "Summary",
                null, mockFile);

        assertThat(result.getTitle()).isEqualTo("Test Title");
        verify(storageService).uploadFile(eq(mockFile), anyString());
        verify(proposalRepository).save(any(Proposal.class));
    }

    @Test
    void deleteProposal_DeletesFileAndRepo() {
        Proposal p = new Proposal();
        p.setId("id1");
        p.setFileName("file.pdf");

        proposalService.deleteProposal(p);

        verify(storageService).deleteFile("file.pdf");
        verify(proposalRepository).deleteById("id1");
    }

    @Test
    void updateProposal_WithNewFile_DeletesOldAndSavesNew() throws Exception {
        Proposal existing = new Proposal();
        existing.setFileName("old.pdf");

        MultipartFile newFile = mock(MultipartFile.class);
        when(newFile.isEmpty()).thenReturn(false);
        when(newFile.getOriginalFilename()).thenReturn("new.pdf");

        proposalService.updateProposal(existing, normalUser, "New Title", "Cat", "Dir", "Sum", null, newFile);

        assertThat(existing.getTitle()).isEqualTo("New Title");
        assertThat(existing.getFileName()).endsWith(".pdf");
        verify(storageService).deleteFile("old.pdf");
        verify(storageService).uploadFile(eq(newFile), anyString());
        verify(proposalRepository).save(existing);
    }

    @Test
    void updateProposal_NoFileChange_UpdatesMetadataOnly() throws Exception {
        Proposal existing = new Proposal();
        existing.setFileName("keep.pdf");

        proposalService.updateProposal(existing, normalUser, "Updated", "Cat", "Dir", "Sum", null, null);

        assertThat(existing.getTitle()).isEqualTo("Updated");
        verify(storageService, never()).deleteFile(anyString());
        verify(storageService, never()).uploadFile(any(), anyString());
    }

    @Test
    void isDuplicateTitle_Exists_ReturnsTrue() {
        when(proposalRepository.findByCreatorIdAndTitle("user1", "Title")).thenReturn(Optional.of(new Proposal()));
        assertThat(proposalService.isDuplicateTitle("user1", "Title")).isTrue();
    }

    @Test
    void isDuplicateTitle_NotExists_ReturnsFalse() {
        when(proposalRepository.findByCreatorIdAndTitle("user1", "Title")).thenReturn(Optional.empty());
        assertThat(proposalService.isDuplicateTitle("user1", "Title")).isFalse();
    }

    @Test
    void createProposal_WithTeamMembers_ParsesJson() throws Exception {
        MultipartFile mockFile = mock(MultipartFile.class);
        when(mockFile.getOriginalFilename()).thenReturn("test.pdf");
        String json = "[{\"name\":\"Member 1\", \"employeeId\":\"E123\"}]";

        when(proposalRepository.save(any(Proposal.class))).thenAnswer(i -> i.getArguments()[0]);

        Proposal result = proposalService.createProposal(normalUser, "Title", "Cat", "Dir", "Sum", json, mockFile);

        assertThat(result.getTeamMembers()).hasSize(1);
        assertThat(result.getTeamMembers().get(0).getName()).isEqualTo("Member 1");
    }
}
