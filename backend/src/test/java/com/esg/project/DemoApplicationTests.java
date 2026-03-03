package com.esg.project;

import com.esg.project.repository.AuditLogRepository;
import com.esg.project.repository.ProposalRepository;
import com.esg.project.repository.SettingRepository;
import com.esg.project.repository.UserRepository;
import com.esg.project.service.StorageService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.mongo.MongoAutoConfiguration;

@SpringBootTest(properties = {
    "spring.mongodb.uri=mongodb://localhost:27017/test",
    "spring.security.user.password=test-password",
    "minio.url=http://localhost:9000",
    "minio.access-key=test",
    "minio.secret-key=test",
    "minio.bucket-name=test"
})
@EnableAutoConfiguration(exclude = {MongoAutoConfiguration.class})
class DemoApplicationTests {

    @MockitoBean
    private AuditLogRepository auditLogRepository;

    @MockitoBean
    private ProposalRepository proposalRepository;

    @MockitoBean
    private SettingRepository settingRepository;

    @MockitoBean
    private UserRepository userRepository;

    @MockitoBean
    private StorageService storageService;

    @Test
    void contextLoads() {
    }

}
