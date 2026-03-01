package com.example.demo.repository;

import com.example.demo.model.Setting;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface SettingRepository extends MongoRepository<Setting, String> {
    Optional<Setting> findByKey(String key);
}
