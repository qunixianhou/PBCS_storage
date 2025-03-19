package org.example;

import static spark.Spark.*;
import java.io.InputStream;
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
        log("WebSocket client connected: " + session.getRemoteAddress().getAddress());
        // 发送历史日志
        for (String log : logQueue) {
            try {
                session.getRemote().sendString(log);
            } catch (Exception e) {
                log("Failed to send log to client: " + e.getMessage());
            }
        }
    }

    @OnWebSocketClose
    public void onClose(Session session, int statusCode, String reason) {
        sessions.remove(session);
        log("WebSocket client disconnected: " + session.getRemoteAddress().getAddress() + ", reason: " + reason);
    }

    @OnWebSocketMessage
    public void onMessage(Session session, String message) {
        log("Received message from client: " + message);
        // 可选：处理前端发送的消息
    }

    private static void broadcastLog(String log) {
        for (Session session : sessions) {
            try {
                if (session.isOpen()) {
                    session.getRemote().sendString(log);
                }
            } catch (Exception e) {
                log("Failed to broadcast log: " + e.getMessage());
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