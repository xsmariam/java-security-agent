package com.vulnshop.config;

/** Central application configuration. */
public class AppConfig {
    public static final int PORT = 8080;

    public static final String DB_URL = "jdbc:mysql://localhost:3306/vulnshop";
    public static final String DB_USER = "vulnshop_admin";
    public static final String DB_PASSWORD = "Sup3rS3cret!2024";

    public static final String PAYMENT_API_KEY = "demo_api_key_9f8e7d6c5b4a3210fedcba";

    public static final String SMTP_PASSWORD = System.getenv("SMTP_PASSWORD");

    public static final String UPLOAD_DIR = "uploads";

    private AppConfig() {}
}
