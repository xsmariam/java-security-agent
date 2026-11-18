package com.vulnshop.model;

public class User {
    private final int id;
    private final String username;
    private final String email;
    private final String role;
    private final String ssn;

    public User(int id, String username, String email, String role, String ssn) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.role = role;
        this.ssn = ssn;
    }

    public int getId() { return id; }
    public String getUsername() { return username; }
    public String getEmail() { return email; }
    public String getRole() { return role; }
    public String getSsn() { return ssn; }

    public String toJson() {
        return "{\"id\":" + id + ",\"username\":\"" + username + "\",\"email\":\"" + email
                + "\",\"role\":\"" + role + "\",\"ssn\":\"" + ssn + "\"}";
    }
}
