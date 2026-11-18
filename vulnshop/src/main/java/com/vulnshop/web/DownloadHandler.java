package com.vulnshop.web;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.vulnshop.config.AppConfig;
import com.vulnshop.util.HttpUtil;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public class DownloadHandler implements HttpHandler {
    @Override
    public void handle(HttpExchange ex) throws IOException {
        String name = HttpUtil.queryParams(ex).get("name");
        File baseDir = new File(AppConfig.UPLOAD_DIR).getCanonicalFile();
        File file = new File(baseDir, name).getCanonicalFile();
        if (!file.toPath().startsWith(baseDir.toPath()) || !file.isFile()) {
            HttpUtil.send(ex, 404, "text/plain", "Not found");
            return;
        }
        HttpUtil.send(ex, 200, "text/plain", new String(Files.readAllBytes(file.toPath())));
    }
}
