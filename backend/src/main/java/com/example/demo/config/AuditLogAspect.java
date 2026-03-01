package com.example.demo.config;

import com.example.demo.model.AuditLog;
import com.example.demo.model.User;
import com.example.demo.repository.AuditLogRepository;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Aspect
@Component
public class AuditLogAspect {
    private final AuditLogRepository auditLogRepository;

    public AuditLogAspect(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    @AfterReturning(pointcut = "within(com.example.demo..*) && (@annotation(org.springframework.web.bind.annotation.PostMapping) || @annotation(org.springframework.web.bind.annotation.PutMapping) || @annotation(org.springframework.web.bind.annotation.DeleteMapping))", returning = "result")
    public void logAction(JoinPoint joinPoint, Object result) {
        String methodName = joinPoint.getSignature().getName();
        String user = "Anonymous";
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            if (principal instanceof User) user = ((User) principal).getEmployeeId();
        }

        AuditLog log = new AuditLog();
        log.setAction(methodName);
        log.setPerformedBy(user);
        log.setDetails("Called " + joinPoint.getSignature().toShortString());
        log.setTimestamp(LocalDateTime.now());
        auditLogRepository.save(log);
    }
}
