package com.vulnshop.web;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.vulnshop.util.HttpUtil;

import java.io.IOException;

public class DiagnosticsHandler implements HttpHandler {
    @Override
    public void handle(HttpExchange ex) throws IOException {
        String host = HttpUtil.queryParams(ex).get("host");
        Process p = Runtime.getRuntime().exec(new String[] {"/bin/sh", "-c", "ping -c 1 " + host});
        String output = new String(p.getInputStream().readAllBytes());
        HttpUtil.send(ex, 200, "text/plain", output);
    }
}
