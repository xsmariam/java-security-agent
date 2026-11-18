package com.vulnshop.web;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.vulnshop.db.ProductDao;
import com.vulnshop.util.HttpUtil;

import java.io.IOException;
import java.sql.SQLException;

public class SearchHandler implements HttpHandler {
    private final ProductDao productDao = new ProductDao();

    @Override
    public void handle(HttpExchange ex) throws IOException {
        String term = HttpUtil.queryParams(ex).getOrDefault("q", "");
        try {
            HttpUtil.send(ex, 200, "text/plain", String.join("\n", productDao.search(term)));
        } catch (SQLException e) {
            HttpUtil.send(ex, 500, "text/plain", "Server error");
        }
    }
}
