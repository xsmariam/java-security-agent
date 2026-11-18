package com.vulnshop.web;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.vulnshop.util.HttpUtil;
import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class XmlImportHandler implements HttpHandler {
    @Override
    public void handle(HttpExchange ex) throws IOException {
        String xml = HttpUtil.readBody(ex);
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
            int count = doc.getElementsByTagName("product").getLength();
            HttpUtil.send(ex, 200, "text/plain", "Imported " + count + " products");
        } catch (Exception e) {
            HttpUtil.send(ex, 400, "text/plain", "Invalid XML");
        }
    }
}
