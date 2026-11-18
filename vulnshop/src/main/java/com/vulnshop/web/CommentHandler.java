package com.vulnshop.web;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.vulnshop.util.HttpUtil;

import java.io.IOException;

public class CommentHandler implements HttpHandler {
    @Override
    public void handle(HttpExchange ex) throws IOException {
        String text = HttpUtil.queryParams(ex).getOrDefault("text", "");
        String html = "<html><body><h2>Your comment</h2><p>" + text + "</p></body></html>";
        HttpUtil.send(ex, 200, "text/html", html);
    }
}
