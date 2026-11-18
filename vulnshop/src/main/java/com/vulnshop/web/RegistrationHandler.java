package com.vulnshop.web;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.vulnshop.auth.AuthService;
import com.vulnshop.db.UserDao;
import com.vulnshop.util.HttpUtil;

import java.io.IOException;
import java.sql.SQLException;
import java.util.Map;

public class RegistrationHandler implements HttpHandler {
    private final UserDao userDao = new UserDao();
    private final AuthService auth;

    public RegistrationHandler(AuthService auth) {
        this.auth = auth;
    }

    @Override
    public void handle(HttpExchange ex) throws IOException {
        Map<String, String> form = HttpUtil.parseParams(HttpUtil.readBody(ex));
        String username = form.get("username");
        String email = form.get("email");
        String password = form.get("password");
        try {
            userDao.create(username, email, auth.hashPassword(password));
            HttpUtil.send(ex, 201, "text/plain", "Registered " + username);
        } catch (SQLException e) {
            HttpUtil.send(ex, 500, "text/plain", "Server error");
        }
    }
}
