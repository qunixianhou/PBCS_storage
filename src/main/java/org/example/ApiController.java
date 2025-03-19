package org.example;

import com.google.gson.Gson;
import spark.Request;
import spark.Response;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;

import static spark.Spark.*;

public class ApiController {
    private static final Gson gson = new Gson();
    private static final String BUCKET_NAME = "test-bucket";
    private static final String LOCAL_S3_PATH = "DataFile/local-s3";

    public static void initRoutes() {
        post("/api/authenticate", ApiController::authenticate);
        post("/api/upload", ApiController::uploadFile);
        post("/api/view", ApiController::viewFile);
        get("/api/registeredUsers", ApiController::getRegisteredUsers);
        post("/api/viewDecrypted", ApiController::viewDecryptedFile); // 新增接口
    }

    private static String authenticate(Request req, Response res) {
        try {
            String userId = req.queryParams("userId");
            String passphrase = req.queryParams("passphrase");

            if (userId == null || passphrase == null) {
                res.status(400);
                return gson.toJson(new ResponseMessage("用户ID和密码不能为空"));
            }

            res.type("application/json");
            if (isUserRegistered(userId)) {
                boolean authenticated = authenticateUser(userId, passphrase);
                if (authenticated) {
                    return gson.toJson(new ResponseMessage("登录成功"));
                } else {
                    res.status(401);
                    return gson.toJson(new ResponseMessage("密码错误"));
                }
            } else {
                Client client = new Client(BUCKET_NAME, LOCAL_S3_PATH, userId);
                client.register(userId, passphrase, BUCKET_NAME, userId + "/sid");
                return gson.toJson(new ResponseMessage("注册成功"));
            }
        } catch (Exception e) {
            res.status(400);
            String message = e.getMessage().contains("already registered") ? "用户已注册" : "操作失败: " + e.getMessage();
            return gson.toJson(new ResponseMessage(message));
        }
    }

    private static String uploadFile(Request req, Response res) {
        try {
            String userId = req.queryParams("userId");
            String passphrase = req.queryParams("passphrase");
            String filePath = saveUploadedFile(req);

            // 使用 AuthServer.getInstance() 检查用户是否注册
            if (!AuthServer.getInstance().isUserRegistered(userId)) {
                res.status(400);
                return gson.toJson(new ResponseMessage("用户未注册，请先认证"));
            }

            Client client = new Client(BUCKET_NAME, LOCAL_S3_PATH, userId);
            client.start(filePath, passphrase);

            res.type("application/json");
            return gson.toJson(new ResponseMessage("文件上传和加密成功"));
        } catch (Exception e) {
            res.status(500);
            return gson.toJson(new ResponseMessage("上传失败: " + e.getMessage()));
        }
    }

    private static String viewFile(Request req, Response res) {
        try {
            String userId = req.queryParams("userId");
            String passphrase = req.queryParams("passphrase");

            Client client = new Client(BUCKET_NAME, LOCAL_S3_PATH, userId);

            // 检查是否存在加密文件
            File secureFile = new File(Constants.FILE_PATH + userId + "/secureRetrieve");
            File optSecureFilePart1 = new File(Constants.FILE_PATH + userId + "/optSecureRetrievePart1");

            String encryptedContent;
            if (secureFile.exists()) {
                System.out.println("Viewing single-threaded encrypted file: " + secureFile.getPath());
                encryptedContent = readFileAsString(secureFile);
            } else if (optSecureFilePart1.exists()) {
                int partNum = 0;
                while (new File(Constants.FILE_PATH + userId + "/optSecureRetrievePart" + (partNum + 1)).exists()) {
                    partNum++;
                }
                if (partNum == 0) {
                    throw new Exception("No parts found for encrypted file prefix: " + optSecureFilePart1.getPath());
                }
                System.out.println("Detected " + partNum + " parts for encrypted file: " + optSecureFilePart1.getPath());
                StringBuilder combinedContent = new StringBuilder();
                for (int i = 1; i <= partNum; i++) {
                    File partFile = new File(Constants.FILE_PATH + userId + "/optSecureRetrievePart" + i);
                    combinedContent.append(readFileAsString(partFile));
                }
                encryptedContent = combinedContent.toString();
            } else {
                throw new Exception("No encrypted files found for user ID: " + userId);
            }

            res.type("text/plain; charset=utf-8");
            System.out.println("Returning encrypted content for user: " + userId);
            return encryptedContent; // 直接返回加密内容
        } catch (Exception e) {
            res.status(500);
            res.type("application/json");
            System.out.println("View failed: " + e.getMessage());
            return gson.toJson(new ResponseMessage("查看失败: " + e.getMessage()));
        }
    }

    // 辅助方法：读取文件内容为字符串
    private static String readFileAsString(File file) throws IOException {
        byte[] content = Files.readAllBytes(file.toPath());
        return Utils.bytesToHex(content); // 转换为十六进制字符串，便于显示
    }
    private static String getRegisteredUsers(Request req, Response res) {
        try {
            System.out.println("Received GET request for /api/registeredUsers");
            List<String> registeredUsers = AuthServer.getInstance().getRegisteredUserIds();
            res.type("application/json");
            System.out.println("Returning registered users: " + registeredUsers);
            return gson.toJson(registeredUsers);
        } catch (Exception e) {
            res.status(500);
            System.err.println("Error in getRegisteredUsers: " + e.getMessage());
            e.printStackTrace();
            return gson.toJson(new ResponseMessage("获取用户列表失败: " + e.getMessage()));
        }
    }

    private static boolean isUserRegistered(String userId) {
        return AuthServer.getInstance().isUserRegistered(userId);
    }

    private static boolean authenticateUser(String userId, String passphrase) throws Exception {
        return AuthServer.getInstance().authenticateUser(userId, passphrase);
    }

    private static String saveUploadedFile(Request req) throws Exception {
        String fileName = req.headers("X-File-Name");
        if (fileName == null) {
            throw new Exception("未提供文件名");
        }
        String filePath = "DataFile/" + fileName;
        File file = new File(filePath);
        file.getParentFile().mkdirs();
        try (java.io.FileOutputStream fos = new java.io.FileOutputStream(file)) {
            fos.write(req.bodyAsBytes());
        }
        return filePath;
    }

    static class ResponseMessage {
        String message;
        ResponseMessage(String message) {
            this.message = message;
        }
    }
    private static String viewDecryptedFile(Request req, Response res) {
        try {
            String userId = req.queryParams("userId");
            String passphrase = req.queryParams("passphrase");

            Client client = new Client(BUCKET_NAME, LOCAL_S3_PATH, userId);
            byte[] decryptedContent = client.viewDecrypted(passphrase); // 调用新方法

            res.type("text/plain; charset=utf-8"); // 返回纯文本
            return new String(decryptedContent, StandardCharsets.UTF_8); // 直接返回解密内容
        } catch (Exception e) {
            res.status(500);
            res.type("application/json");
            return gson.toJson(new ResponseMessage("解密查看失败: " + e.getMessage()));
        }
    }
}