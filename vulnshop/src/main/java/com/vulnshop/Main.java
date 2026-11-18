package com.vulnshop;

import com.sun.net.httpserver.HttpServer;
import com.vulnshop.auth.AuthService;
import com.vulnshop.config.AppConfig;
import com.vulnshop.web.*;

import java.io.IOException;
import java.net.InetSocketAddress;

public class Main {
    public static void main(String[] args) throws IOException {
        AuthService auth = new AuthService();
        HttpServer server = HttpServer.create(new InetSocketAddress(AppConfig.PORT), 0);

        server.createContext("/login", new LoginHandler(auth));
        server.createContext("/register", new RegistrationHandler(auth));
        server.createContext("/profile", new ProfileHandler(auth));
        server.createContext("/admin", new AdminHandler());
        server.createContext("/search", new SearchHandler());
        server.createContext("/files", new FileHandler());
        server.createContext("/download", new DownloadHandler());
        server.createContext("/comment", new CommentHandler());
        server.createContext("/ping", new DiagnosticsHandler());
        server.createContext("/import", new XmlImportHandler());

        server.start();
        System.out.println("VulnShop listening on port " + AppConfig.PORT);
    }
}
