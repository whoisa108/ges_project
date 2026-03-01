package com.example.demo.repository;

import com.example.demo.model.Proposal;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Optional;

@Repository
public interface ProposalRepository extends MongoRepository<Proposal, String> {
    List<Proposal> findByCreatorId(String creatorId);
    Optional<Proposal> findByCreatorIdAndTitle(String creatorId, String title);
}
