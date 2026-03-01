package com.esg.project;

import com.esg.project.model.User;
import com.esg.project.model.Setting;
import com.esg.project.repository.UserRepository;
import com.esg.project.repository.SettingRepository;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.time.LocalDateTime;

@SpringBootApplication
public class DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }

    @Bean
    public CommandLineRunner initAdmin(UserRepository repo, BCryptPasswordEncoder encoder) {
        return args -> {
            if (repo.findByEmployeeId("admin").isEmpty()) {
                User admin = new User();
                admin.setEmployeeId("admin");
                admin.setName("Administrator");
                admin.setPassword(encoder.encode("admin123"));
                admin.setRole("ADMIN");
                admin.setDepartment("SYSTEM");
                admin.setNeedsPasswordReset(true);
                repo.save(admin);
            }
        };
    }

    @Bean
    public CommandLineRunner initDeadline(SettingRepository repo) {
        return args -> {
            if (repo.findByKey("deadline").isEmpty()) {
                Setting setting = new Setting();
                setting.setKey("deadline");
                setting.setValue(LocalDateTime.of(2026, 3, 17, 23, 59, 59).toString());
                repo.save(setting);
            }
        };
    }
}
