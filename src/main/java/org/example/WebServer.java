package org.example;

import static spark.Spark.*;
import java.io.InputStream;

public class WebServer {
    public static void main(String[] args) {
        port(8080);

        serveStaticFiles();
        ApiController.initRoutes();

        Thread authServerThread = new Thread(() -> {
            try {
                AuthServer authServer = AuthServer.getInstance();
                System.out.println("Starting AuthServer...");
                authServer.start();
            } catch (Exception e) {
                System.err.println("AuthServer failed: " + e.getMessage());
                e.printStackTrace();
            }
        });
        authServerThread.setDaemon(true);
        authServerThread.start();

        System.out.println("WebServer started at http://localhost:8080");
    }

    private static void serveStaticFiles() {
        get("/", (req, res) -> {
            res.type("text/html");
            InputStream inputStream = WebServer.class.getResourceAsStream("/static/index.html");
            if (inputStream == null) {
                res.status(404);
                return "index.html not found";
            }
            return new String(inputStream.readAllBytes());
        });

        get("/static/app.js", (req, res) -> {
            res.type("application/javascript");
            InputStream inputStream = WebServer.class.getResourceAsStream("/static/app.js");
            if (inputStream == null) {
                res.status(404);
                return "app.js not found";
            }
            return new String(inputStream.readAllBytes());
        });
    }
}