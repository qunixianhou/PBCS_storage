package org.example;

import static spark.Spark.*;
import java.io.InputStream;
import java.util.Iterator;
import java.util.concurrent.ConcurrentLinkedQueue;

import org.eclipse.jetty.websocket.api.Session;
import org.eclipse.jetty.websocket.api.annotations.*;

@WebSocket
public class WebServer {
    private static final ConcurrentLinkedQueue<Session> sessions = new ConcurrentLinkedQueue<>();
    private static final ConcurrentLinkedQueue<String> logQueue = new ConcurrentLinkedQueue<>();

    public static void main(String[] args) {
        port(8080);

        // 在所有路由映射之前注册 WebSocket
        webSocket("/logs", WebServer.class);

        // 然后注册静态文件服务和 API 路由
        serveStaticFiles();
        ApiController.initRoutes();

        // 启动 AuthServer 线程
        Thread authServerThread = new Thread(() -> {
            try {
                AuthServer authServer = AuthServer.getInstance();
                log("Starting AuthServer...");
                authServer.start();
            } catch (Exception e) {
                log("AuthServer failed: " + e.getMessage());
                e.printStackTrace();
            }
        });
        authServerThread.setDaemon(true);
        authServerThread.start();

        // 重定向 System.out 到日志队列
        System.setOut(new java.io.PrintStream(new java.io.OutputStream() {
            final StringBuilder buffer = new StringBuilder();
            @Override
            public void write(int b) {
                char c = (char) b;
                if (c == '\n') {
                    String log = buffer.toString();
                    logQueue.add(log);
                    broadcastLog(log);
                    buffer.setLength(0);
                } else {
                    buffer.append(c);
                }
            }

            @Override
            public void write(byte[] b, int off, int len) {
                String line = new String(b, off, len);
                logQueue.add(line);
                broadcastLog(line);
            }
        }));

        log("WebServer started at http://localhost:8080");
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
        get("/static/*", (req, res) -> {
            String path = "/static/" + req.splat()[0];
            InputStream inputStream = WebServer.class.getResourceAsStream(path);
            if (inputStream == null) {
                res.status(404);
                return "Resource not found";
            }
            if (path.endsWith(".js")) res.type("application/javascript");
            else if (path.endsWith(".css")) res.type("text/css");
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

    @OnWebSocketConnect
    public void onConnect(Session session) {
        sessions.add(session);
        log("WebSocket", "Connected", "Client connected: " + session.getRemoteAddress().getAddress());
        // 发送历史日志
        for (String log : logQueue) {
            try {
                session.getRemote().sendString(log);
            } catch (Exception e) {
                log("WebSocket", "Error", "Failed to send log to client: " + e.getMessage());
            }
        }
    }

    @OnWebSocketClose
    public void onClose(Session session, int statusCode, String reason) {
        sessions.remove(session);
        log("WebSocket", "Disconnected", "Client disconnected: " + session.getRemoteAddress().getAddress() + ", reason: " + reason);
    }

    @OnWebSocketMessage
    public void onMessage(Session session, String message) {
        log("WebSocket", "Message", "Received from client: " + message);
    }
    // 统一日志方法
    public static void log(String component, String status, String description) {
        String logMessage = String.format("[%s] %s %s", component, status, description);
        System.out.println(logMessage); // 输出到控制台
        logQueue.add(logMessage);
        broadcastLog(logMessage);
    }
    // 重载方法，带用户ID
    public static void log(String userId, String operation, String status, String description) {
        String logMessage = String.format("[%s] %s %s %s", userId, operation, status, description);
        System.out.println(logMessage); // 输出到控制台
        logQueue.add(logMessage);
        broadcastLog(logMessage);
    }

    private static void broadcastLog(String log) {
        Iterator<Session> iterator = sessions.iterator();
        while (iterator.hasNext()) {
            Session session = iterator.next();
            try {
                if (session.isOpen()) {
                    session.getRemote().sendString(log);
                } else {
                    iterator.remove(); // 移除已关闭的会话
                }
            } catch (Exception e) {
                log("Failed to broadcast log to session: " + e.getMessage());
            }
        }
    }

    // 辅助方法，用于将日志记录到队列和控制台
    private static void log(String message) {
        System.out.println(message); // 保留控制台输出，便于调试
        logQueue.add(message);
        broadcastLog(message);
    }
}