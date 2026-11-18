package com.vulnshop.web;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.vulnshop.auth.AuthService;
import com.vulnshop.util.HttpUtil;

import java.io.IOException;
import java.sql.SQLException;
import java.util.Map;

public class LoginHandler implements HttpHandler {
    private final AuthService auth;

    public LoginHandler(AuthService auth) {
        this.auth = auth;
    }

    @Override
    public void handle(HttpExchange ex) throws IOException {
        Map<String, String> form = HttpUtil.parseParams(HttpUtil.readBody(ex));
        try {
            String token = auth.login(form.get("username"), form.get("password"));
            if (token == null) {
                HttpUtil.send(ex, 401, "text/plain", "Invalid credentials");
            } else {
                HttpUtil.send(ex, 200, "application/json", "{\"token\":\"" + token + "\"}");
            }
        } catch (SQLException e) {
            HttpUtil.send(ex, 500, "text/plain", "Server error");
        }
    }
}
