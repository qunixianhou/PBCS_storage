package org.example;

import static spark.Spark.*;

import java.net.URL;

public class WebServer {
    public static void main(String[] args) throws Exception {
        port(8080);

        // 调试类路径资源
        URL appJsUrl = WebServer.class.getResource("/static/app.js");
        System.out.println("app.js URL: " + appJsUrl);
        if (appJsUrl == null) {
            System.err.println("Error: /static/app.js not found in classpath!");
        } else {
            System.out.println("app.js content exists: " + (WebServer.class.getResourceAsStream("/static/app.js") != null));
        }

        // 配置静态文件
        staticFiles.location("/static"); // 从类路径加载 /static
        System.out.println("Static files configured at: /static");

        // 手动测试静态文件访问
        get("/static/app.js", (req, res) -> {
            res.type("application/javascript");
            byte[] content = WebServer.class.getResourceAsStream("/static/app.js").readAllBytes();
            if (content == null || content.length == 0) {
                res.status(404);
                return "File not found";
            }
            return content;
        });

        // 根路径返回 index.html
        get("/", (req, res) -> {
            res.type("text/html");
            byte[] content = WebServer.class.getResourceAsStream("/static/index.html").readAllBytes();
            if (content == null || content.length == 0) {
                res.status(404);
                return "Index not found";
            }
            return content;
        });

        // 测试路由
        get("/test", (req, res) -> "Hello, World!");
    }
}