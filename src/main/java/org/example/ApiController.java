package org.example;

import com.google.gson.Gson;
import spark.Request;
import spark.Response;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
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
        post("/api/view", ApiController::viewEncryptedFile);
        get("/api/registeredUsers", ApiController::getRegisteredUsers);
        post("/api/viewDecrypted", ApiController::viewDecryptedFile);
    }

    private static String authenticate(Request req, Response res) {
        try {
            String userId = req.queryParams("userId");
            String passphrase = req.queryParams("passphrase");

            if (userId == null || passphrase == null) {
                res.status(400);
                return gson.toJson(new ResponseMessage("User ID and passphrase cannot be empty"));
            }

            WebServer.log(userId, "Authentication", "Started", "User authentication initiated");
            res.type("application/json");
            if (isUserRegistered(userId)) {
                boolean authenticated = authenticateUser(userId, passphrase);
                if (authenticated) {
                    WebServer.log(userId, "Authentication", "Completed", "User authenticated successfully");
                    return gson.toJson(new ResponseMessage("Login successful"));
                } else {
                    res.status(401);
                    return gson.toJson(new ResponseMessage("Incorrect passphrase"));
                }
            } else {
                Client client = new Client(BUCKET_NAME, LOCAL_S3_PATH, userId);
                client.register(userId, passphrase, BUCKET_NAME, userId + "/sid");
                WebServer.log(userId, "Authentication", "Completed", "New user registered successfully");
                return gson.toJson(new ResponseMessage("Registration successful"));
            }
        } catch (Exception e) {
            res.status(400);
            String message = e.getMessage().contains("already registered") ? "User already registered" : "Operation failed: " + e.getMessage();
            return gson.toJson(new ResponseMessage(message));
        }
    }

    private static String uploadFile(Request req, Response res) {
        try {
            String userId = req.queryParams("userId");
            String passphrase = req.queryParams("passphrase");
            WebServer.log(userId, "File Upload", "Started", "Initiating file upload and encryption");

            if (!AuthServer.getInstance().isUserRegistered(userId)) {
                res.status(400);
                return gson.toJson(new ResponseMessage("User not registered, please authenticate first"));
            }

            String filePath = saveUploadedFile(req);
            String originalFileName = URLDecoder.decode(req.headers("X-File-Name"), StandardCharsets.UTF_8.name()); // 解码文件名
            Client client = new Client(BUCKET_NAME, LOCAL_S3_PATH, userId);
            String key0 = userId + "/sid";
            String key1 = userId + "/rid";
            String key4 = userId + "/oneThreadEncryptedFile";
            String internalCipherFilePath = Constants.FILE_PATH + userId + "/internalSingleThreadEncryptedFile";

            String hardenedPWD = client.ibOPRF(userId, passphrase);
            byte[] msk = client.give(userId, passphrase, BUCKET_NAME, key1, key0);
            client.secureDeposit(BUCKET_NAME, key4, msk, filePath, internalCipherFilePath);

            // 保存文件名到文件系统中
            File nameFile = new File(Constants.FILE_PATH + userId + "/originalFileName.txt");
            Files.write(nameFile.toPath(), originalFileName.getBytes(StandardCharsets.UTF_8));

            WebServer.log(userId, "File Upload", "Completed", "File uploaded and encrypted successfully");
            res.type("application/json");
            return gson.toJson(new ResponseMessage("File uploaded and encrypted successfully"));
        } catch (Exception e) {
            res.status(500);
            return gson.toJson(new ResponseMessage("Upload failed: " + e.getMessage()));
        }
    }
    private static String viewEncryptedFile(Request req, Response res) {
        try {
            String userId = req.queryParams("userId");
            String passphrase = req.queryParams("passphrase");
            WebServer.log(userId, "View Encrypted File", "Started", "Retrieving encrypted file");

            if (!AuthServer.getInstance().isUserRegistered(userId)) {
                res.status(400);
                return gson.toJson(new ResponseMessage("User not registered, please authenticate first"));
            }

            Client client = new Client(BUCKET_NAME, LOCAL_S3_PATH, userId);
            String key0 = userId + "/sid";
            String key4 = userId + "/oneThreadEncryptedFile";
            String encryptedFilePath = Constants.FILE_PATH + userId + "/secureRetrieve";

            byte[] sid = getSid(userId);
            byte[] computedT = Utils.KDF(sid, passphrase, Constants.KDF1_SALT, Constants.MAC_KEY_LENGTH, Constants.KDF_HASH_REPETITIONS);
            byte[] registeredT = AuthServer.getInstance().usersReg.get(userId).t;

            if (!Arrays.equals(computedT, registeredT)) {
                res.status(401);
                return gson.toJson(new ResponseMessage("Authentication failed: Incorrect passphrase"));
            }

            client.secureRetrieve(BUCKET_NAME, key4, encryptedFilePath);
            File encryptedFile = new File(encryptedFilePath);
            if (!encryptedFile.exists()) {
                throw new Exception("Encrypted file not found");
            }

            byte[] encryptedContent;
            try (InputStream in = new FileInputStream(encryptedFile)) {
                encryptedContent = in.readAllBytes();
            }

            res.type("application/octet-stream");
            res.header("Content-Disposition", "attachment; filename=\"encrypted_file.bin\"");
            res.raw().setContentLength(encryptedContent.length);
            res.raw().getOutputStream().write(encryptedContent);
            res.raw().getOutputStream().flush();
            res.raw().getOutputStream().close();

            WebServer.log(userId, "View Encrypted File", "Completed", "Encrypted file retrieved successfully");
            return null;
        } catch (Exception e) {
            res.status(500);
            res.type("application/json");
            return gson.toJson(new ResponseMessage("Failed to view encrypted file: " + e.getMessage()));
        }
    }
    private static String getRegisteredUsers(Request req, Response res) {
        try {
            String userId = req.queryParams("userId") != null ? req.queryParams("userId") : "System";
            WebServer.log(userId, "Query Registered Users", "Started", "Fetching user list");

            List<String> registeredUsers = AuthServer.getInstance().getRegisteredUserIds();
            WebServer.log(userId, "Query Registered Users", "Completed", "User list retrieved successfully");

            res.type("application/json");
            return gson.toJson(registeredUsers);
        } catch (Exception e) {
            res.status(500);
            return gson.toJson(new ResponseMessage("Failed to get user list: " + e.getMessage()));
        }
    }

    private static String viewDecryptedFile(Request req, Response res) {
        try {
            String userId = req.queryParams("userId");
            String passphrase = req.queryParams("passphrase");
            WebServer.log(userId, "Decrypt and View", "Started", "Initiating file decryption");

            if (!AuthServer.getInstance().isUserRegistered(userId)) {
                res.status(400);
                return gson.toJson(new ResponseMessage("User not registered, please authenticate first"));
            }

            Client client = new Client(BUCKET_NAME, LOCAL_S3_PATH, userId);
            String key0 = userId + "/sid";
            String key1 = userId + "/rid";
            String encryptedFilePath = Constants.FILE_PATH + userId + "/secureRetrieve";

            byte[] sid = getSid(userId);
            byte[] computedT = Utils.KDF(sid, passphrase, Constants.KDF1_SALT, Constants.MAC_KEY_LENGTH, Constants.KDF_HASH_REPETITIONS);
            byte[] registeredT = AuthServer.getInstance().usersReg.get(userId).t;

            if (!Arrays.equals(computedT, registeredT)) {
                res.status(401);
                return gson.toJson(new ResponseMessage("Authentication failed: Incorrect passphrase"));
            }

            byte[] mskr = client.take(userId, passphrase, BUCKET_NAME, key1, key0);
            if (mskr == null) {
                throw new Exception("Failed to retrieve decryption key");
            }

            File encryptedFile = new File(encryptedFilePath);
            if (!encryptedFile.exists()) {
                throw new Exception("Encrypted file not found, please upload first");
            }

            byte[] decryptedContent = client.decryptCTRBigFileToBytes(encryptedFilePath, mskr);
            Utils.destroyPasskey(mskr);

            String originalFileName;
            File nameFile = new File(Constants.FILE_PATH + userId + "/originalFileName.txt");
            if (nameFile.exists()) {
                originalFileName = new String(Files.readAllBytes(nameFile.toPath()), StandardCharsets.UTF_8);
            } else {
                originalFileName = "decrypted_file.unknown";
            }

            String mimeType = originalFileName.endsWith(".txt") ? "text/plain" :
                    (originalFileName.matches(".*\\.(jpg|jpeg|png|gif)$") ?
                            "image/" + originalFileName.substring(originalFileName.lastIndexOf(".") + 1).toLowerCase() :
                            "application/octet-stream");

            res.type(mimeType);
            res.header("Content-Disposition", "inline; filename=\"" + originalFileName + "\"");
            res.header("X-File-Name", originalFileName);
            res.raw().setContentLength(decryptedContent.length);
            res.raw().getOutputStream().write(decryptedContent);
            res.raw().getOutputStream().flush();
            res.raw().getOutputStream().close();

            WebServer.log(userId, "Decrypt and View", "Completed", "File decrypted and sent successfully");
            return null;
        } catch (Exception e) {
            res.status(500);
            res.type("application/json");
            return gson.toJson(new ResponseMessage("Failed to decrypt and view: " + e.getMessage()));
        }
    }
    private static byte[] getSid(String userId) throws Exception {
        try {
            final LocalS3Client s3 = LocalS3Client.Builder.standard().withBaseDirectory(LOCAL_S3_PATH).build();
            LocalS3Client.S3Object object = s3.getObject(new LocalS3Client.GetObjectRequest(BUCKET_NAME, userId + "/sid"));
            return object.getObjectContent().readAllBytes();
        } catch (Exception e) {
            throw new Exception("Failed to retrieve SID: " + e.getMessage());
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
            throw new Exception("File name not provided");
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
        return Utils.bytesToHex(content);
    }

    static class ResponseMessage {
        String message;
        ResponseMessage(String message) {
            this.message = message;
        }
    }
}