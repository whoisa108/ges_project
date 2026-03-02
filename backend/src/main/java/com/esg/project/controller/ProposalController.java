package com.esg.project.controller;

import com.esg.project.model.User;
import com.esg.project.model.Proposal;
import com.esg.project.service.ProposalService;
import com.esg.project.service.StorageService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/proposals")
public class ProposalController {
    private final ProposalService proposalService;
    private final StorageService storageService;

    public ProposalController(ProposalService proposalService, StorageService storageService) {
        this.proposalService = proposalService;
        this.storageService = storageService;
    }

    @GetMapping
    public List<Proposal> getProposals() {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return proposalService.getProposals(user);
    }

    @PostMapping
    public ResponseEntity<?> createProposal(
            @RequestParam("title") String title,
            @RequestParam("category") String category,
            @RequestParam("direction") String direction,
            @RequestParam("summary") String summary,
            @RequestParam(value = "teamMembers", required = false) String teamMembersJson,
            @RequestParam("file") MultipartFile file) {
        
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        if (proposalService.isDuplicateTitle(user.getEmployeeId(), title)) {
            return ResponseEntity.badRequest().body("Duplicate proposal title for this user");
        }

        if (proposalService.isDeadlinePassed()) {
            return ResponseEntity.badRequest().body("Competition deadline has passed");
        }

        try {
            Proposal p = proposalService.createProposal(user, title, category, direction, summary, teamMembersJson, file);
            return ResponseEntity.ok(p);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteProposal(@PathVariable String id) {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        Optional<Proposal> p = proposalService.findById(id);
        
        if (p.isPresent()) {
            if ("ADMIN".equals(user.getRole()) || p.get().getCreatorId().equals(user.getEmployeeId())) {
                proposalService.deleteProposal(p.get());
                return ResponseEntity.ok("Deleted");
            }
            return ResponseEntity.status(403).body("Forbidden");
        }
        return ResponseEntity.notFound().build();
    }

    @PostMapping("/{id}")
    public ResponseEntity<?> updateProposal(
            @PathVariable String id,
            @RequestParam("title") String title,
            @RequestParam("category") String category,
            @RequestParam("direction") String direction,
            @RequestParam("summary") String summary,
            @RequestParam(value = "teamMembers", required = false) String teamMembersJson,
            @RequestParam(value = "file", required = false) MultipartFile file) {
        
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        Optional<Proposal> pOpt = proposalService.findById(id);
        
        if (pOpt.isEmpty()) return ResponseEntity.notFound().build();
        Proposal p = pOpt.get();

        if (!p.getCreatorId().equals(user.getEmployeeId())) {
            return ResponseEntity.status(403).body("Only creator can edit");
        }

        if (proposalService.isDeadlinePassed()) {
            return ResponseEntity.badRequest().body("Competition deadline has passed");
        }

        try {
            proposalService.updateProposal(p, user, title, category, direction, summary, teamMembersJson, file);
            return ResponseEntity.ok(p);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }

    @GetMapping("/{id}/download")
    public ResponseEntity<?> downloadFile(@PathVariable String id) {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        Optional<Proposal> pOpt = proposalService.findById(id);
        
        if (pOpt.isEmpty()) return ResponseEntity.notFound().build();
        Proposal p = pOpt.get();

        if (!"ADMIN".equals(user.getRole()) && !p.getCreatorId().equals(user.getEmployeeId())) {
            return ResponseEntity.status(403).build();
        }

        try {
            io.minio.GetObjectResponse response = storageService.getFile(p.getFileName());
            return ResponseEntity.ok()
                    .header("Content-Disposition", "attachment; filename=\"" + p.getFileName() + "\"")
                    .header("Content-Type", response.headers().get("Content-Type"))
                    .body(new org.springframework.core.io.InputStreamResource(response));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("Download failed: " + e.getMessage());
        }
    }
}
