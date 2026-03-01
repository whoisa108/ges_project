package com.esg.project.service;

import com.esg.project.model.User;
import com.esg.project.model.Proposal;
import com.esg.project.model.Setting;
import com.esg.project.model.TeamMember;
import com.esg.project.repository.ProposalRepository;
import com.esg.project.repository.SettingRepository;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Service
public class ProposalService {
    private final ProposalRepository proposalRepository;
    private final SettingRepository settingRepository;
    private final StorageService storageService;

    public ProposalService(ProposalRepository proposalRepository, SettingRepository settingRepository, StorageService storageService) {
        this.proposalRepository = proposalRepository;
        this.settingRepository = settingRepository;
        this.storageService = storageService;
    }

    public List<Proposal> getProposals(User user) {
        if ("ADMIN".equals(user.getRole())) return proposalRepository.findAll();
        return proposalRepository.findByCreatorId(user.getEmployeeId());
    }

    public Optional<Proposal> findById(String id) {
        return proposalRepository.findById(id);
    }

    public boolean isDeadlinePassed() {
        Optional<Setting> deadline = settingRepository.findByKey("deadline");
        return deadline.isPresent() && LocalDateTime.now().isAfter(LocalDateTime.parse(deadline.get().getValue()));
    }

    public boolean isDuplicateTitle(String creatorId, String title) {
        return proposalRepository.findByCreatorIdAndTitle(creatorId, title).isPresent();
    }

    public Proposal createProposal(User user, String title, String category, String direction, String summary, String teamMembersJson, MultipartFile file) throws Exception {
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
            List<TeamMember> teamMembers = new ObjectMapper().readValue(teamMembersJson, new TypeReference<List<TeamMember>>() {});
            p.setTeamMembers(teamMembers);
        }

        return proposalRepository.save(p);
    }

    public void deleteProposal(Proposal p) {
        if (p.getFileName() != null) {
            storageService.deleteFile(p.getFileName());
        }
        proposalRepository.deleteById(p.getId());
    }

    public void updateProposal(Proposal p, User user, String title, String category, String direction, String summary, String teamMembersJson, MultipartFile file) throws Exception {
        p.setTitle(title);
        p.setCategory(category);
        p.setDirection(direction);
        p.setSummary(summary);

        if (teamMembersJson != null && !teamMembersJson.isEmpty()) {
            List<TeamMember> teamMembers = new ObjectMapper().readValue(teamMembersJson, new TypeReference<List<TeamMember>>() {});
            p.setTeamMembers(teamMembers);
        }

        if (file != null && !file.isEmpty()) {
            if (p.getFileName() != null) storageService.deleteFile(p.getFileName());
            String originalExt = file.getOriginalFilename().substring(file.getOriginalFilename().lastIndexOf("."));
            String fileName = category + "_" + user.getDepartment() + "_" + user.getName() + "_" + user.getEmployeeId() + "_" + title + originalExt;
            storageService.uploadFile(file, fileName);
            p.setFileName(fileName);
        }
        proposalRepository.save(p);
    }
}
