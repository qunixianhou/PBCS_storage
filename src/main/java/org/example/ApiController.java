package org.example;

import com.google.gson.Gson;
import spark.Request;
import spark.Response;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.List;

import static spark.Spark.*;

public class ApiController {
    static final Gson gson = new Gson();
    private static final String BUCKET_NAME = "test-bucket";
    private static final String LOCAL_S3_PATH = "DataFile/local-s3";

    public static void initRoutes() {
        post("/api/authenticate", ApiController::authenticate);
        post("/api/upload", ApiController::uploadFile);
        post("/api/view", ApiController::viewEncryptedFile); // 重命名为更明确的目的
        get("/api/registeredUsers", ApiController::getRegisteredUsers);
        post("/api/viewDecrypted", ApiController::viewDecryptedFile);
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

            if (!AuthServer.getInstance().isUserRegistered(userId)) {
                res.status(400);
                return gson.toJson(new ResponseMessage("用户未注册，请先认证"));
            }

            Client client = new Client(BUCKET_NAME, LOCAL_S3_PATH, userId);
            // 修改上传逻辑，仅存储加密文件
            String key0 = userId + "/sid";
            String key1 = userId + "/rid";
            String key4 = userId + "/oneThreadEncryptedFile";
            String internalCipherFilePath = Constants.FILE_PATH + userId + "/internalSingleThreadEncryptedFile";

            // 密码硬化
            String hardenedPWD = client.ibOPRF(userId, passphrase);
            // 密钥存款
            byte[] msk = client.give(userId, passphrase, BUCKET_NAME, key1, key0);
            // 加密并上传文件（单线程版本）
            client.secureDeposit(BUCKET_NAME, key4, msk, filePath, internalCipherFilePath);

            res.type("application/json");
            return gson.toJson(new ResponseMessage("文件上传和加密成功"));
        } catch (Exception e) {
            res.status(500);
            return gson.toJson(new ResponseMessage("上传失败: " + e.getMessage()));
        }
    }

    private static String viewEncryptedFile(Request req, Response res) {
        try {
            String userId = req.queryParams("userId");
            String passphrase = req.queryParams("passphrase");
            System.out.println("Attempting to view encrypted file for user: " + userId);

            if (!AuthServer.getInstance().isUserRegistered(userId)) {
                res.status(400);
                return gson.toJson(new ResponseMessage("用户未注册，请先认证"));
            }

            Client client = new Client(BUCKET_NAME, LOCAL_S3_PATH, userId);
            String key0 = userId + "/sid"; // sid 的存储路径
            String key4 = userId + "/oneThreadEncryptedFile";
            String encryptedFilePath = Constants.FILE_PATH + userId + "/secureRetrieve";

            // 从 LocalS3Client 获取 sid
            byte[] sid;
            try {
                final LocalS3Client s3 = LocalS3Client.Builder.standard().withBaseDirectory(LOCAL_S3_PATH).build();
                LocalS3Client.S3Object object = s3.getObject(new LocalS3Client.GetObjectRequest(BUCKET_NAME, key0));
                sid = object.getObjectContent().readAllBytes();
            } catch (Exception e) {
                throw new Exception("无法获取 sID: " + e.getMessage());
            }

            // 使用 sid 和 passphrase 计算 t
            byte[] computedT = Utils.KDF(sid, passphrase, Constants.KDF1_SALT, Constants.MAC_KEY_LENGTH, Constants.KDF_HASH_REPETITIONS);
            byte[] registeredT = AuthServer.getInstance().usersReg.get(userId).t;

            // 比较注册时和计算出的 t 值
            if (!Arrays.equals(computedT, registeredT)) {
                res.status(401);
                System.out.println("Authentication failed: t values do not match");
                return gson.toJson(new ResponseMessage("认证失败：密码错误"));
            }

            // 认证通过后检索加密文件
            client.secureRetrieve(BUCKET_NAME, key4, encryptedFilePath);

            // 读取加密文件内容
            File encryptedFile = new File(encryptedFilePath);
            if (!encryptedFile.exists()) {
                throw new Exception("加密文件不存在");
            }
            String encryptedContent = readFileAsString(encryptedFile);

            res.type("text/plain; charset=utf-8");
            System.out.println("Returning encrypted content for user: " + userId);
            return encryptedContent;
        } catch (Exception e) {
            res.status(500);
            res.type("application/json");
            System.out.println("View encrypted file failed: " + e.getMessage());
            return gson.toJson(new ResponseMessage("查看加密文件失败: " + e.getMessage()));
        }
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

    private static String viewDecryptedFile(Request req, Response res) {
        try {
            String userId = req.queryParams("userId");
            String passphrase = req.queryParams("passphrase");
            System.out.println("Attempting to view decrypted file for user: " + userId);

            if (!AuthServer.getInstance().isUserRegistered(userId)) {
                res.status(400);
                return gson.toJson(new ResponseMessage("用户未注册，请先认证"));
            }

            Client client = new Client(BUCKET_NAME, LOCAL_S3_PATH, userId);
            String key0 = userId + "/sid";
            String key1 = userId + "/rid";
            String encryptedFilePath = Constants.FILE_PATH + userId + "/secureRetrieve";

            // 从 LocalS3Client 获取 sid
            byte[] sid;
            try {
                final LocalS3Client s3 = LocalS3Client.Builder.standard().withBaseDirectory(LOCAL_S3_PATH).build();
                LocalS3Client.S3Object object = s3.getObject(new LocalS3Client.GetObjectRequest(BUCKET_NAME, key0));
                sid = object.getObjectContent().readAllBytes();
            } catch (Exception e) {
                throw new Exception("无法获取 sID: " + e.getMessage());
            }

            // 使用 sid 和 passphrase 计算 t
            byte[] computedT = Utils.KDF(sid, passphrase, Constants.KDF1_SALT, Constants.MAC_KEY_LENGTH, Constants.KDF_HASH_REPETITIONS);
            byte[] registeredT = AuthServer.getInstance().usersReg.get(userId).t;

            if (!Arrays.equals(computedT, registeredT)) {
                res.status(401);
                System.out.println("Authentication failed: t values do not match");
                return gson.toJson(new ResponseMessage("认证失败：密码错误"));
            }

            // 认证通过后，获取 mskr
            byte[] mskr = client.take(userId, passphrase, BUCKET_NAME, key1, key0);
            if (mskr == null) {
                throw new Exception("无法检索解密密钥");
            }

            // 确保加密文件存在
            File encryptedFile = new File(encryptedFilePath);
            if (!encryptedFile.exists()) {
                throw new Exception("加密文件不存在，请先上传文件");
            }

            // 解密文件
            byte[] decryptedContent = client.decryptCTRBigFileToBytes(encryptedFilePath, mskr);
            Utils.destroyPasskey(mskr); // 清理密钥

            res.type("text/plain; charset=utf-8");
            System.out.println("Returning decrypted content for user: " + userId);
            return new String(decryptedContent, StandardCharsets.UTF_8);
        } catch (Exception e) {
            res.status(500);
            res.type("application/json");
            System.out.println("View decrypted file failed: " + e.getMessage());
            return gson.toJson(new ResponseMessage("解密查看失败: " + e.getMessage()));
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

    private static String readFileAsString(File file) throws IOException {
        byte[] content = Files.readAllBytes(file.toPath());
        return Utils.bytesToHex(content); // 转换为十六进制字符串
    }

    static class ResponseMessage {
        String message;
        ResponseMessage(String message) {
            this.message = message;
        }
    }
}