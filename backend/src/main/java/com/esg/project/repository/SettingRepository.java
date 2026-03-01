package com.esg.project.repository;

import com.esg.project.model.Setting;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface SettingRepository extends MongoRepository<Setting, String> {
    Optional<Setting> findByKey(String key);
}
