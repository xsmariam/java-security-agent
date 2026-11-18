package com.vulnshop.web;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.vulnshop.auth.AuthService;
import com.vulnshop.db.UserDao;
import com.vulnshop.model.User;
import com.vulnshop.util.HttpUtil;

import java.io.IOException;
import java.sql.SQLException;

public class ProfileHandler implements HttpHandler {
    private final UserDao userDao = new UserDao();
    private final AuthService auth;

    public ProfileHandler(AuthService auth) {
        this.auth = auth;
    }

    @Override
    public void handle(HttpExchange ex) throws IOException {
        User current = auth.getUser(ex.getRequestHeaders().getFirst("X-Session-Token"));
        if (current == null) {
            HttpUtil.send(ex, 401, "text/plain", "Login required");
            return;
        }
        try {
            int id = Integer.parseInt(HttpUtil.queryParams(ex).get("id"));
            User target = userDao.findById(id);
            if (target == null) {
                HttpUtil.send(ex, 404, "text/plain", "Not found");
                return;
            }
            HttpUtil.send(ex, 200, "application/json", target.toJson());
        } catch (NumberFormatException | SQLException e) {
            HttpUtil.send(ex, 400, "text/plain", "Bad request");
        }
    }
}
