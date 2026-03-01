package com.esg.project.model;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Document(collection = "users")
public class User {
    @Id private String id;
    private String employeeId;
    private String name;
    private String department;
    private String password;
    private String role;
    private boolean needsPasswordReset;

    // Getters and Setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getEmployeeId() { return employeeId; }
    public void setEmployeeId(String employeeId) { this.employeeId = employeeId; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getDepartment() { return department; }
    public void setDepartment(String department) { this.department = department; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }
    public boolean isNeedsPasswordReset() { return needsPasswordReset; }
    public void setNeedsPasswordReset(boolean needsPasswordReset) { this.needsPasswordReset = needsPasswordReset; }
}
