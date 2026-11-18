package com.vulnshop.web;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.vulnshop.config.AppConfig;
import com.vulnshop.util.HttpUtil;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public class FileHandler implements HttpHandler {
    @Override
    public void handle(HttpExchange ex) throws IOException {
        String name = HttpUtil.queryParams(ex).get("name");
        File file = new File(AppConfig.UPLOAD_DIR + "/" + name);
        if (!file.exists()) {
            HttpUtil.send(ex, 404, "text/plain", "Not found");
            return;
        }
        HttpUtil.send(ex, 200, "text/plain", new String(Files.readAllBytes(file.toPath())));
    }
}
