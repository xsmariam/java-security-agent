package com.vulnshop.web;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.vulnshop.db.UserDao;
import com.vulnshop.model.User;
import com.vulnshop.util.HttpUtil;

import java.io.IOException;
import java.sql.SQLException;
import java.util.Map;
import java.util.stream.Collectors;

public class AdminHandler implements HttpHandler {
    private final UserDao userDao = new UserDao();

    @Override
    public void handle(HttpExchange ex) throws IOException {
        Map<String, String> params = HttpUtil.queryParams(ex);
        try {
            if (params.containsKey("delete")) {
                userDao.delete(Integer.parseInt(params.get("delete")));
                HttpUtil.send(ex, 200, "text/plain", "Deleted");
                return;
            }
            String json = userDao.findAll().stream().map(User::toJson).collect(Collectors.joining(",", "[", "]"));
            HttpUtil.send(ex, 200, "application/json", json);
        } catch (NumberFormatException | SQLException e) {
            HttpUtil.send(ex, 400, "text/plain", "Bad request");
        }
    }
}
