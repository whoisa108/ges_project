package com.esg.project.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import java.time.LocalDateTime;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "proposals")
public class Proposal {
    @Id private String id;
    private String creatorId;
    private String creatorName;
    private String category;
    private String direction;
    private String title;
    private String summary;
    private String fileName;
    private List<TeamMember> teamMembers;
    private LocalDateTime createdAt;
}
