package org.example;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.math.ec.ECPoint;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.SocketFactory;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.*;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CopyOnWriteArrayList;

public class Client {
    private SocketFactory socketFactory;
    private Logger logger;
    private int kdfHashRepetitions;
    public final String bucketName;
    private final String localS3Path;
    private static final boolean verbose = true;
    private String secureRetFilePath;
    private String internalCipherFilePath;
    private String plainFilePath;
    private String optSecureRetFilePath;
    private String encryptionFilePath;
    private String decryptionFilePath;
    private final String userID;

    SimpleEcCurve curve = new SimpleEcCurve(Constants.CURVE_NAME);

    public interface Logger {
        void log(String tag, String message);
        void log(String message);
    }

    public Client(String bucketName, String localS3Path, String userID) {
        this(SocketFactory.getDefault(), new Logger() {
            @Override
            public void log(String message) {
                System.out.println(message);
            }
            @Override
            public void log(String tag, String message) {
                log(tag + ": " + message);
            }
        }, Constants.KDF_HASH_REPETITIONS, bucketName, localS3Path, userID);
    }

    public Client(SocketFactory socketFactory, Logger logger, int kdfHashRepetitions, String bucketName, String localS3Path, String userID) {
        this.socketFactory = socketFactory;
        this.logger = logger;
        this.kdfHashRepetitions = kdfHashRepetitions;
        this.bucketName = bucketName;
        this.localS3Path = localS3Path;
        this.userID = userID;
        this.secureRetFilePath = Paths.get(Constants.FILE_PATH, userID, "secureRetrieve").toString();
        this.internalCipherFilePath = Paths.get(Constants.FILE_PATH, userID, "internal").toString() + File.separator;
        this.plainFilePath = Paths.get(Constants.FILE_PATH, userID, "plain").toString();
        this.optSecureRetFilePath = Paths.get(Constants.FILE_PATH, userID, "optSecureRetrieve").toString();
        this.encryptionFilePath = Paths.get(Constants.FILE_PATH, userID, "encryption").toString();
        this.decryptionFilePath = Paths.get(Constants.FILE_PATH, userID, "decryption").toString();
    }

    private void ensureDirectoryExists(String filePath) {
        File file = new File(filePath);
        File parentDir = file.getParentFile();
        if (parentDir != null && !parentDir.exists()) {
            boolean created = parentDir.mkdirs();
            if (!created) {
                throw new RuntimeException("Failed to create directory: " + parentDir.getAbsolutePath());
            }
        }
    }

    public void start(String sourceFilePath, String passphrase) throws Exception {
        String key0 = userID + "/sid";
        String key1 = userID + "/rid";
        String key2 = userID + "/optimizedEncryptedFile";
        String key4 = userID + "/oneThreadEncryptedFile";

        byte[] msk, mskr;
        int partNum;
        String hardenedPWD, hardenedPWD1;

        // 1. 密码硬化
        if (verbose) logger.log("PASSWORD HARDENING PROTOCOL");
        hardenedPWD = ibOPRF(userID, passphrase);

        // 2. 如果已注册，跳过注册步骤
        if (!AuthServer.getInstance().isUserRegistered(userID)) {
            register(userID, passphrase, bucketName, key0);
        }

        // 3. 再次密码硬化
        if (verbose) logger.log("PASSWORD HARDENING PROTOCOL");
        hardenedPWD = ibOPRF(userID, passphrase);

        // 4. 密钥存款
        if (verbose) logger.log("KEY DEPOSIT PROTOCOL");
        msk = give(userID, passphrase, bucketName, key1, key0);

        // 5. 加密并上传文件（优化版本）
        if (verbose) logger.log("ENCRYPT AND UPLOAD FILE (OPTIMIZED)");
        partNum = secureDepositOptimization(bucketName, key2, msk, sourceFilePath);

        // 6. 再次密码硬化
        if (verbose) logger.log("PASSWORD HARDENING PROTOCOL");
        hardenedPWD1 = ibOPRF(userID, passphrase);

        // 7. 密钥检索
        if (verbose) logger.log("KEY RETRIEVAL PROTOCOL\n");
        mskr = take(userID, passphrase, bucketName, key1, key0);
        if (!Arrays.equals(msk, mskr)) {
            throw new Exception("msk does not match mskr");
        }

        // 8. 下载加密文件（优化版本）
        if (verbose) logger.log("RETRIEVE ENCRYPTED FILE (OPTIMIZED)");
        secureRetrieveOptimization(partNum, bucketName, key2, optSecureRetFilePath, mskr);

        // 9. 加密并上传文件（单线程版本）
        if (verbose) logger.log("ENCRYPT AND UPLOAD FILE (SINGLE-THREAD)");
        secureDeposit(bucketName, key4, msk, sourceFilePath, internalCipherFilePath + "singleThreadEncryptedFile");

        // 10. 下载加密文件（单线程版本）
        if (verbose) logger.log("RETRIEVE ENCRYPTED FILE (SINGLE-THREAD)");
        secureRetrieve(bucketName, key4, secureRetFilePath);

        // 11. 检查硬化密码一致性
        if (!hardenedPWD1.equals(hardenedPWD)) {
            logger.log("The hardened password is " + hardenedPWD + " and " + hardenedPWD1);
        }
    }

    public String ibOPRF(String userID, String passphrase) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] message = passphrase.getBytes(StandardCharsets.UTF_8);

        MessageDigest hash = MessageDigest.getInstance("SHA-256");

        ECPoint hashPoint = curve.hash2Curve(message, hash);

        BigInteger k = curve.randomBigInteger(random);
        ECPoint blindPoint = hashPoint.multiply(k).normalize();
        byte[] blindPointBytes = blindPoint.getEncoded(true);

        Socket authServerSock = SocketFactory.getDefault().createSocket(Constants.AUTH_SERVER_ADDRESS, Constants.AUTH_SERVER_PORT_NUMBER);
        OutputStream out = authServerSock.getOutputStream();
        out.write(Constants.REQ_TYPE_AUTHSERVER_OPRF);
        out.write(userID.getBytes().length);
        out.write(userID.getBytes());

        out.write(blindPointBytes.length);
        out.write(blindPointBytes);

        InputStream in = authServerSock.getInputStream();
        byte depositAuthServerResponse = (byte) in.read();
        switch (depositAuthServerResponse) {
            case Constants.RESP_TYPE_OK:
                if (verbose) logger.log("Deposit protocol succeeded.");
                break;
            case Constants.RESP_TYPE_ERROR:
                throw new Exception("Auth Server error in Deposit Protocol!");
            default:
                throw new Exception("Auth Server error in Deposit Protocol!");
        }

        byte[] blindedecPointBytes = new byte[in.read()];
        in.read(blindedecPointBytes);
        ECPoint blindedecPoint = curve.ecDomainParameters.getCurve().decodePoint(blindedecPointBytes);

        BigInteger kInv = k.modInverse(curve.n);
        ECPoint bEcPointDerive = blindedecPoint.multiply(kInv).normalize();
        byte[] bEcPointDeriveByte = bEcPointDerive.getEncoded(true);
        BigInteger hardenedPWD = curve.hashToGroup2(bEcPointDeriveByte, passphrase.getBytes(StandardCharsets.UTF_8));

        authServerSock.close();

        return hardenedPWD.toString();
    }

    public void register(String userID, String passphrase, String bucketName, String key0) throws Exception {
        byte[] sid = new byte[Constants.R_LENGTH];
        Random rand = new Random();
        rand.nextBytes(sid);

        try {
            final LocalS3Client s3 = LocalS3Client.Builder.standard().withBaseDirectory(this.localS3Path).build();
            s3.putObject(new LocalS3Client.PutObjectRequest(bucketName, key0, createFileFromByte(sid)));
        } catch (Exception e) {
            System.out.println("Error in local S3 operation: " + e.getMessage());
            throw e;
        }
        byte[] t = Utils.KDF(sid, passphrase, Constants.KDF1_SALT, Constants.MAC_KEY_LENGTH, kdfHashRepetitions);
        Socket authServerSock = SocketFactory.getDefault().createSocket(Constants.AUTH_SERVER_ADDRESS, Constants.AUTH_SERVER_PORT_NUMBER);

        OutputStream out = authServerSock.getOutputStream();
        out.write(Constants.REQ_TYPE_AUTHSERVER_REGISTER);
        out.write(userID.getBytes().length);
        out.write(userID.getBytes());
        out.write(t.length);
        out.write(t);

        InputStream in = authServerSock.getInputStream();
        byte depositAuthServerResponse = (byte) in.read();
        switch (depositAuthServerResponse) {
            case Constants.RESP_TYPE_OK:
                if (verbose) logger.log("Register protocol succeeded.");
                break;
            case Constants.RESP_TYPE_ERROR:
                throw new Exception("Auth Server error in Register Protocol!");
            default:
                throw new Exception("Auth Server error in Register Protocol!");
        }
        authServerSock.close();
    }

    public byte[] give(String userID, String passphrase, String bucketName, String key1, String key0) throws Exception {
        Socket authServerSock = SocketFactory.getDefault().createSocket(Constants.AUTH_SERVER_ADDRESS, Constants.AUTH_SERVER_PORT_NUMBER);

        byte[] rid = new byte[Constants.R_LENGTH];
        byte[] sid = new byte[Constants.R_LENGTH];
        Random rand = new Random();
        rand.nextBytes(rid);
        byte[] parameter = new byte[Constants.R_LENGTH];
        System.arraycopy(rid, 0, parameter, 0, Constants.R_LENGTH);

        try {
            final LocalS3Client s3 = LocalS3Client.Builder.standard().withBaseDirectory(this.localS3Path).build();
            s3.putObject(new LocalS3Client.PutObjectRequest(bucketName, key1, createFileFromByte(parameter)));
            LocalS3Client.S3Object object = s3.getObject(new LocalS3Client.GetObjectRequest(bucketName, key0));
            sid = IOUtils.toByteArray(object.getObjectContent());
        } catch (Exception e) {
            System.out.println("Caught an AmazonServiceException: " + e.getMessage());
            throw e;
        }

        KeyGenerator kgen = KeyGenerator.getInstance(Constants.DATA_ENCRYPTION_BASE_ALGORITHM);
        byte[] msk = kgen.generateKey().getEncoded();

        if (verbose) logger.log("Generated msk: " + Utils.bytesToHex(msk));
        byte[] t = Utils.KDF(sid, passphrase, Constants.KDF1_SALT, Constants.MAC_KEY_LENGTH, kdfHashRepetitions);
        byte[] k1 = Utils.KDF(rid, passphrase, Constants.KDF2_SALT, Constants.ENC_KEY_LENGTH, kdfHashRepetitions);
        byte[] k2 = Utils.KDF(rid, passphrase, Constants.KDF3_SALT, Constants.ENC_KEY_LENGTH, kdfHashRepetitions);

        Cipher cipher = Cipher.getInstance(Constants.KEY_ENCRYPTION_ALGORITHM);
        SecretKey keyEncryptionKey = new SecretKeySpec(k1, Constants.KEY_ENCRYPTION_BASE_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keyEncryptionKey);
        byte[] ct = cipher.doFinal(msk);
        byte[] iv = cipher.getIV();

        ByteArrayOutputStream ivCt = new ByteArrayOutputStream();
        ivCt.write(iv);
        ivCt.write(ct);
        byte[] ivct = ivCt.toByteArray();
        byte[] tao = Utils.KDF(ivct, Arrays.toString(k2), Constants.KDF4_SALT, Constants.ENC_KEY_LENGTH, kdfHashRepetitions);

        OutputStream out = authServerSock.getOutputStream();
        out.write(Constants.REQ_TYPE_AUTHSERVER_DEPOSIT);
        out.write(userID.getBytes().length);
        out.write(userID.getBytes());
        out.write(t.length);
        out.write(t);
        out.write(tao.length);
        out.write(tao);
        out.write(ivct.length);
        out.write(ivct);

        InputStream in = authServerSock.getInputStream();
        byte depositAuthServerResponse = (byte) in.read();
        switch (depositAuthServerResponse) {
            case Constants.RESP_TYPE_OK:
                if (verbose) logger.log("Deposit protocol succeeded.");
                break;
            case Constants.RESP_TYPE_ERROR:
                throw new Exception("Auth Server error in Deposit Protocol!");
            default:
                throw new Exception("Auth Server error in Deposit Protocol!");
        }

        authServerSock.close();
        return msk;
    }

    public byte[] take(String userID, String passphrase, String bucketName, String key1, String key0) throws Exception {
        byte[] sid = new byte[Constants.R_LENGTH];
        byte[] rid = new byte[Constants.R_LENGTH];

        try {
            final LocalS3Client s3 = LocalS3Client.Builder.standard()
                    .withBaseDirectory(this.localS3Path)
                    .build();
            if (verbose) System.out.println("Retrieve parameter\n");
            LocalS3Client.S3Object object = s3.getObject(new LocalS3Client.GetObjectRequest(bucketName, key1));
            byte[] encryptedData = IOUtils.toByteArray(object.getObjectContent());
            rid = Arrays.copyOfRange(encryptedData, 0, Constants.R_LENGTH);
            LocalS3Client.S3Object object2 = s3.getObject(new LocalS3Client.GetObjectRequest(bucketName, key0));
            sid = IOUtils.toByteArray(object2.getObjectContent());
        } catch (Exception e) {
            System.out.println("Error in local S3 operation: " + e.getMessage());
            throw e;
        }

        byte[] t = Utils.KDF(sid, passphrase, Constants.KDF1_SALT, Constants.MAC_KEY_LENGTH, kdfHashRepetitions);
        byte[] k1 = Utils.KDF(rid, passphrase, Constants.KDF2_SALT, Constants.ENC_KEY_LENGTH, kdfHashRepetitions);
        byte[] k2 = Utils.KDF(rid, passphrase, Constants.KDF3_SALT, Constants.ENC_KEY_LENGTH, kdfHashRepetitions);

        Socket authServerSock = SocketFactory.getDefault().createSocket(Constants.AUTH_SERVER_ADDRESS, Constants.AUTH_SERVER_PORT_NUMBER);
        OutputStream out = authServerSock.getOutputStream();

        out.write(Constants.REQ_TYPE_AUTHSERVER_RETRIEVAL);
        out.write(userID.getBytes().length);
        out.write(userID.getBytes());
        out.write(t);

        InputStream in = authServerSock.getInputStream();
        byte retrievalAuthServerResponse = (byte) in.read();
        switch (retrievalAuthServerResponse) {
            case Constants.RESP_TYPE_OK:
                if (verbose) logger.log("Retrieval protocol succeeded.");
                break;
            case Constants.RESP_TYPE_ERROR:
                logger.log("Retrieval failed! (Auth Server returned error)");
                throw new Exception("Auth Server error in Retrieval Protocol!");
            default:
                logger.log("Received unexpected response from server.");
                throw new Exception("Auth Server error in Retrieval Protocol!");
        }

        byte[] ct = new byte[in.read() - Constants.KEY_ENCRYPTION_IV_LENGTH];
        byte[] iv = new byte[Constants.KEY_ENCRYPTION_IV_LENGTH];
        in.read(iv);
        in.read(ct);
        byte[] tao = new byte[in.read()];
        in.read(tao);
        ByteArrayOutputStream ivCt = new ByteArrayOutputStream();
        ivCt.write(iv);
        ivCt.write(ct);
        byte[] ivct = ivCt.toByteArray();

        byte[] taoCal = Utils.KDF(ivct, Arrays.toString(k2), Constants.KDF4_SALT, Constants.ENC_KEY_LENGTH, kdfHashRepetitions);
        if (!Arrays.equals(tao, taoCal)) {
            logger.log("User " + userID + " did not take a valid tao. Retrieval request ignored.");
        }

        Cipher cipher = Cipher.getInstance(Constants.KEY_ENCRYPTION_ALGORITHM);
        SecretKey keyEncryptionKey = new SecretKeySpec(k1, Constants.KEY_ENCRYPTION_BASE_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keyEncryptionKey, new GCMParameterSpec(Constants.GCM_TAG_LENGTH, iv));
        byte[] mskr = cipher.doFinal(ct);
        System.out.println("Retrieved mskr: " + Utils.bytesToHex(mskr));
        authServerSock.close();
        return mskr;
    }

    public void secureDeposit(String bucketName, String key2, byte[] msk, String sourceFilePath, String internalCipherFilePath)
            throws Exception {
        logger.log("[" + userID + "] File Upload Started Initiating file upload and encryption");

        // Encrypt file using msk
        encryptCTRBigFile(sourceFilePath, internalCipherFilePath, msk);

        // Upload to S3
        try {
            final LocalS3Client s3 = LocalS3Client.Builder.standard()
                    .withBaseDirectory(this.localS3Path)
                    .build();
            s3.setBucketAccelerateConfiguration(new LocalS3Client.SetBucketAccelerateConfigurationRequest(bucketName,
                    new LocalS3Client.BucketAccelerateConfiguration("Enabled")));
            s3.putObject(new LocalS3Client.PutObjectRequest(bucketName, key2, new File(internalCipherFilePath)));
            logger.log("[" + userID + "] File Upload Completed File uploaded and encrypted successfully");
        } catch (Exception e) {
            logger.log("[" + userID + "] File Upload Failed: " + e.getMessage());
            throw e;
        }
    }

    private void encryptCTRBigFile(String sourcePath, String targetPath, byte[] msk) throws Exception {
        logger.log("Encrypting file: " + sourcePath);
        File inputFile = new File(sourcePath);
        logger.log("Input file size: " + inputFile.length());

        // Check BOM
        try (FileInputStream in = new FileInputStream(inputFile)) {
            byte[] bom = new byte[2];
            if (in.read(bom) >= 2) {
                String bomHex = Utils.bytesToHex(bom);
                logger.log("BOM (first 2 bytes): " + bomHex);
                if (bom[0] == (byte) 0xFF && bom[1] == (byte) 0xFE) {
                    logger.log("Detected UTF-16LE encoding");
                } else if (bom[0] == (byte) 0xFE && bom[1] == (byte) 0xFF) {
                    logger.log("Detected UTF-16BE encoding");
                } else {
                    logger.log("No UTF-16 BOM detected, assuming raw bytes");
                }
            }
        }

        ensureDirectoryExists(targetPath);

        try (FileInputStream in = new FileInputStream(inputFile);
             FileOutputStream out = new FileOutputStream(targetPath)) {
            // Generate random dataKey
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            kgen.init(128);
            byte[] dataKey = kgen.generateKey().getEncoded();
            logger.log("Generated dataKey: " + Utils.bytesToHex(dataKey));

            // Encrypt dataKey with msk (AES/GCM)
            Cipher keyCipher = Cipher.getInstance("AES/GCM/NoPadding");
            byte[] keyIv = new byte[Constants.KEY_ENCRYPTION_IV_LENGTH];
            SecureRandom.getInstanceStrong().nextBytes(keyIv);
            keyCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(msk, "AES"),
                    new GCMParameterSpec(Constants.GCM_TAG_LENGTH, keyIv));
            byte[] encryptedDataKey = keyCipher.doFinal(dataKey);
            logger.log("Key IV (GCM): " + Utils.bytesToHex(keyIv));
            logger.log("Encrypted dataKey: " + Utils.bytesToHex(encryptedDataKey));
            logger.log("Encrypted dataKey length: " + encryptedDataKey.length);

            // Generate CTR IV
            byte[] iv = new byte[Constants.KEY_ENCRYPTION_CTR_IV_LENGTH];
            SecureRandom.getInstanceStrong().nextBytes(iv);
            logger.log("CTR IV: " + Utils.bytesToHex(iv));

            // Write header
            out.write(keyIv.length >> 24);
            out.write(keyIv.length >> 16);
            out.write(keyIv.length >> 8);
            out.write(keyIv.length);
            out.write(keyIv);
            out.write(encryptedDataKey.length >> 24);
            out.write(encryptedDataKey.length >> 16);
            out.write(encryptedDataKey.length >> 8);
            out.write(encryptedDataKey.length);
            out.write(encryptedDataKey);
            out.write(iv);

            // Encrypt content
            Cipher fileCipher = Cipher.getInstance("AES/CTR/NoPadding");
            fileCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(dataKey, "AES"), new IvParameterSpec(iv));
            byte[] buffer = new byte[8192];
            int bytesRead;
            long contentWritten = 0;
            while ((bytesRead = in.read(buffer)) != -1) {
                byte[] encrypted = fileCipher.update(buffer, 0, bytesRead);
                if (encrypted != null) {
                    out.write(encrypted);
                    contentWritten += encrypted.length;
                }
            }
            byte[] finalBlock = fileCipher.doFinal();
            if (finalBlock != null) {
                out.write(finalBlock);
                contentWritten += finalBlock.length;
            }
            out.flush();
            logger.log("Encrypted content length: " + contentWritten);
        } catch (Exception e) {
            logger.log("Encryption failed: " + e.getMessage());
            throw e;
        }
        logger.log("File encrypted to: " + targetPath);
    }

    public void secureRetrieve(String bucketName, String key2, String encryptedFilePath) throws IOException {
        if (verbose) {
            logger.log("Retrieving encrypted file from S3 bucket " + bucketName + " with key " + key2);
        }
        try {
            final LocalS3Client s3 = LocalS3Client.Builder.standard()
                    .withBaseDirectory(this.localS3Path)
                    .build();
            s3.setBucketAccelerateConfiguration(new LocalS3Client.SetBucketAccelerateConfigurationRequest(bucketName,
                    new LocalS3Client.BucketAccelerateConfiguration("Enabled")));

            s3.getObject(bucketName, key2, encryptedFilePath);
            File downloadedFile = new File(encryptedFilePath);
            logger.log("Encrypted file downloaded, " + downloadedFile.length() + " bytes saved to " + encryptedFilePath);
        } catch (Exception e) {
            logger.log("Error in secureRetrieve", "Failed to retrieve file: " + e.getMessage());
            throw e instanceof IOException ? (IOException) e : new IOException(e);
        }
    }

    public void secureRetrieveOptimization(int partNum, String bucketName, String key2, String encryptedFilePathPrefix, byte[] msk) throws IOException {
        if (verbose) {
            System.out.format("Retrieving from S3 bucket %s...\n", bucketName);
        }
        try {
            final LocalS3Client s3 = LocalS3Client.Builder.standard()
                    .withBaseDirectory(this.localS3Path)
                    .build();
            s3.setBucketAccelerateConfiguration(new LocalS3Client.SetBucketAccelerateConfigurationRequest(bucketName,
                    new LocalS3Client.BucketAccelerateConfiguration("Enabled")));

            ensureDirectoryExists(encryptedFilePathPrefix + "Part1");

            for (int index = 1; index <= partNum; index++) {
                String partKey = key2 + "/part" + index;
                String encryptedPartPath = encryptedFilePathPrefix + "Part" + index;
                s3.getObject(bucketName, partKey, encryptedPartPath);
                logger.log("Encrypted file part " + index + " saved to " + encryptedPartPath);
            }
        } catch (Exception e) {
            System.out.println("Error in local S3 operation: " + e.getMessage());
            throw e instanceof IOException ? (IOException) e : new IOException(e);
        }
    }

    public int secureDepositOptimization(String bucketName, String key2, byte[] msk, String sourceFilePath) throws Exception {
        int partSize;
        int partNumber;
        List<Integer> indexList = new CopyOnWriteArrayList<>();
        try (FileInputStream fileInputStream = new FileInputStream(sourceFilePath)) {
            double fileSize = fileInputStream.available();
            double sqrtSize = Math.sqrt(fileSize / 1024 / 1024 / 20.0);
            if (sqrtSize > 0 && sqrtSize <= 1) partNumber = 1;
            else partNumber = (int) Math.round(sqrtSize);
            partSize = (int) Math.ceil(fileSize / partNumber);
        }

        List<Integer> encList = new CopyOnWriteArrayList<>();
        // 为每个分片生成数据密钥
        byte[][] dataKeys = new byte[partNumber][];
        byte[][] encryptedDataKeys = new byte[partNumber][];
        byte[][] keyIvs = new byte[partNumber][];
        Cipher keyCipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKey mskKey = new SecretKeySpec(msk, "AES");
        for (int i = 0; i < partNumber; i++) {
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            kgen.init(128);
            dataKeys[i] = kgen.generateKey().getEncoded();
            keyCipher.init(Cipher.ENCRYPT_MODE, mskKey);
            encryptedDataKeys[i] = keyCipher.doFinal(dataKeys[i]);
            keyIvs[i] = keyCipher.getIV();
        }

        Thread threadEnc = new EncThread(encList, partNumber, partSize, sourceFilePath, internalCipherFilePath, dataKeys, encryptedDataKeys, keyIvs);
        threadEnc.start();

        uploadFilePartsToS3(encList, partNumber, internalCipherFilePath, bucketName, key2);
        try {
            threadEnc.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        return partNumber;
    }

    public void uploadFilePartsToS3(List<Integer> list, int partNum, String filePath, String bucketName, String key2) throws IOException {
        final LocalS3Client s3 = LocalS3Client.Builder.standard()
                .withBaseDirectory(this.localS3Path)
                .build();
        s3.setBucketAccelerateConfiguration(new LocalS3Client.SetBucketAccelerateConfigurationRequest(bucketName,
                new LocalS3Client.BucketAccelerateConfiguration("Enabled")));

        int index = 0;
        while (index < partNum) {
            index++;
            while (list.size() < index) ;
            try (InputStream inputStream = new FileInputStream(filePath + "EncPart" + index)) {
                int streamSize = inputStream.available();
                LocalS3Client.ObjectMetadata metadata = new LocalS3Client.ObjectMetadata();
                metadata.setContentLength(streamSize);
                String key2_part = key2 + "/part" + index;

                s3.putObject(new LocalS3Client.PutObjectRequest(bucketName, key2_part, inputStream, metadata));
            }
        }
    }

    private static File createFileFromByte(byte[] input) throws IOException {
        File file = File.createTempFile("aws-java-sdk-", ".txt", null);
        file.deleteOnExit();

        try (FileOutputStream fileOutputStream = new FileOutputStream(file)) {
            fileOutputStream.write(input);
        }
        return file;
    }

    private byte[] decryptCTRBigFile(String sourcePath, byte[] msk) throws Exception {
        logger.log("Decrypting file: " + sourcePath);
        File inputFile = new File(sourcePath);
        logger.log("Encrypted file size: " + inputFile.length());

        try (FileInputStream in = new FileInputStream(inputFile);
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            // Read header: [keyIv.length (4)][keyIv][encryptedDataKey.length (4)][encryptedDataKey][iv]
            if (in.available() < 4) {
                throw new IOException("File too short to contain valid header");
            }
            int keyIvLen = (in.read() << 24) | (in.read() << 16) | (in.read() << 8) | in.read();
            if (keyIvLen < 0 || keyIvLen > 1024) {
                throw new IOException("Invalid keyIv length: " + keyIvLen);
            }
            byte[] keyIv = new byte[keyIvLen];
            int bytesRead = in.read(keyIv);
            if (bytesRead != keyIvLen) {
                throw new IOException("Failed to read keyIv, expected " + keyIvLen + " bytes, got " + bytesRead);
            }
            int encKeyLen = (in.read() << 24) | (in.read() << 16) | (in.read() << 8) | in.read();
            if (encKeyLen < 0 || encKeyLen > 1024) {
                throw new IOException("Invalid encryptedDataKey length: " + encKeyLen);
            }
            byte[] encryptedDataKey = new byte[encKeyLen];
            bytesRead = in.read(encryptedDataKey);
            if (bytesRead != encKeyLen) {
                throw new IOException("Failed to read encryptedDataKey, expected " + encKeyLen + " bytes, got " + bytesRead);
            }
            byte[] iv = new byte[Constants.KEY_ENCRYPTION_CTR_IV_LENGTH];
            bytesRead = in.read(iv);
            if (bytesRead != Constants.KEY_ENCRYPTION_CTR_IV_LENGTH) {
                throw new IOException("IV is empty or incomplete: expected " +
                        Constants.KEY_ENCRYPTION_CTR_IV_LENGTH + " bytes, got " + bytesRead);
            }
            logger.log("Read keyIv: " + Utils.bytesToHex(keyIv));
            logger.log("Read encryptedDataKey: " + Utils.bytesToHex(encryptedDataKey));
            logger.log("Read CTR IV: " + Utils.bytesToHex(iv));

            // Decrypt dataKey with msk (AES/GCM)
            Cipher keyCipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKey mskKey = new SecretKeySpec(msk, "AES");
            byte[] dataKey;
            try {
                keyCipher.init(Cipher.DECRYPT_MODE, mskKey, new GCMParameterSpec(Constants.GCM_TAG_LENGTH, keyIv));
                dataKey = keyCipher.doFinal(encryptedDataKey);
                logger.log("Decrypted dataKey: " + Utils.bytesToHex(dataKey));
            } catch (AEADBadTagException e) {
                logger.log("GCM decryption failed: Invalid tag, keyIv=" + Utils.bytesToHex(keyIv) +
                        ", encryptedDataKey=" + Utils.bytesToHex(encryptedDataKey));
                throw new IOException("GCM decryption failed", e);
            }

            // Decrypt file content with dataKey (AES/CTR)
            Cipher fileCipher = Cipher.getInstance("AES/CTR/NoPadding");
            fileCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(dataKey, "AES"), new IvParameterSpec(iv));
            byte[] buffer = new byte[8192];
            while ((bytesRead = in.read(buffer)) != -1) {
                byte[] decrypted = fileCipher.update(buffer, 0, bytesRead);
                if (decrypted != null) {
                    out.write(decrypted);
                }
            }
            byte[] finalBlock = fileCipher.doFinal();
            if (finalBlock != null) {
                out.write(finalBlock);
            }

            byte[] decryptedData = out.toByteArray();
            logger.log("Decrypted data length: " + decryptedData.length);
            return decryptedData;
        } catch (Exception e) {
            logger.log("Decryption failed: " + e.getMessage());
            throw e;
        }
    }

    public void view(String passphrase) throws Exception {
        String key0 = userID + "/sid";
        String key1 = userID + "/rid";

        File secureFile = new File(secureRetFilePath);
        File optSecureFilePart1 = new File(optSecureRetFilePath + "Part1");

        if (secureFile.exists()) {
            if (verbose) logger.log("Viewing single-threaded encrypted file: " + secureRetFilePath);
            viewSecureFile(userID, passphrase, bucketName, key1, key0);
        } else if (optSecureFilePart1.exists()) {
            int partNum = 0;
            while (new File(optSecureRetFilePath + "Part" + (partNum + 1)).exists()) {
                partNum++;
            }
            if (partNum == 0) {
                throw new Exception("No parts found for encrypted file prefix: " + optSecureRetFilePath);
            }
            if (verbose) logger.log("Detected " + partNum + " parts for encrypted file: " + optSecureRetFilePath);
            viewSecureFileOptimization(userID, passphrase, bucketName, key1, key0, optSecureRetFilePath, partNum);
        } else {
            throw new Exception("No encrypted files found for user ID: " + userID);
        }
    }

    public byte[] viewSecureFile(String userID, String passphrase, String bucketName, String key1, String key0) throws Exception {
        logger.log("[" + userID + "] View Encrypted File Started Retrieving encrypted file");
        LocalS3Client s3Client = new LocalS3Client(localS3Path);

        try {
            // Retrieve msk
            byte[] mskr = take(userID, passphrase, bucketName, key1, key0);
            logger.log("Retrieved mskr: " + Utils.bytesToHex(mskr));

            // Download encrypted file
            String secureRetFilePath = Paths.get("DataFile", userID, "secureRetrieve").toString();
            String s3Key = userID + "/oneThreadEncryptedFile";
            logger.log("Retrieving encrypted file from S3 bucket " + bucketName + " with key " + s3Key);
            s3Client.getObject(bucketName, s3Key, secureRetFilePath);
            File downloadedFile = new File(secureRetFilePath);
            logger.log("Encrypted file downloaded, " + downloadedFile.length() + " bytes saved to " + secureRetFilePath);

            // Decrypt file
            byte[] decryptedData = decryptCTRBigFile(secureRetFilePath, mskr);

            // Save decrypted data as UTF-16LE file
            String decryptedFilePath = Paths.get("DataFile", userID, "decrypted.txt").toString();
            ensureDirectoryExists(decryptedFilePath);
            try (OutputStreamWriter writer = new OutputStreamWriter(
                    new FileOutputStream(decryptedFilePath), StandardCharsets.UTF_16LE)) {
                // Remove BOM if present
                String content = new String(decryptedData, StandardCharsets.UTF_16LE);
                if (decryptedData.length >= 2 && decryptedData[0] == (byte) 0xFF && decryptedData[1] == (byte) 0xFE) {
                    content = content.substring(1); // Skip BOM
                    logger.log("Detected UTF-16LE BOM, removed for output");
                }
                writer.write(content);
            }
            logger.log("Decrypted file saved to: " + decryptedFilePath);

            // Log decrypted content
            String decryptedContent = new String(decryptedData, StandardCharsets.UTF_16LE);
            logger.log("Decrypted content (UTF-16LE): " + decryptedContent);

            // Log BOM and first few bytes for debugging
            if (decryptedData.length >= 2) {
                String bom = Utils.bytesToHex(Arrays.copyOfRange(decryptedData, 0, Math.min(20, decryptedData.length)));
                logger.log("First 20 bytes (hex): " + bom);
            }

            logger.log("[" + userID + "] View Encrypted File Completed Encrypted file retrieved successfully");
            return decryptedData;
        } catch (Exception e) {
            logger.log("[" + userID + "] View Encrypted File Failed: " + e.getMessage());
            throw new Exception("Failed to retrieve and decrypt file", e);
        }
    }

    public void viewSecureFileOptimization(String userID, String passphrase, String bucketName, String key1, String key0,
                                           String encryptedFilePathPrefix, int partNum)
            throws Exception {
        byte[] mskr = take(userID, passphrase, bucketName, key1, key0);
        if (mskr == null) {
            throw new Exception("Failed to retrieve key for user " + userID);
        }

        logger.log("Viewing secure file parts from " + encryptedFilePathPrefix);
        for (int index = 1; index <= partNum; index++) {
            String encryptedPartPath = encryptedFilePathPrefix + "Part" + index;
            try (InputStream encryptedStream = new FileInputStream(encryptedPartPath)) {
                // Read header: [keyIv.length (4)][keyIv][encryptedDataKey.length (4)][encryptedDataKey][iv]
                int keyIvLen = (encryptedStream.read() << 24) | (encryptedStream.read() << 16) |
                        (encryptedStream.read() << 8) | encryptedStream.read();
                if (keyIvLen < 0 || keyIvLen > 1024) {
                    throw new IOException("Invalid keyIv length: " + keyIvLen);
                }
                byte[] keyIv = new byte[keyIvLen];
                int bytesRead = encryptedStream.read(keyIv);
                if (bytesRead != keyIvLen) {
                    throw new IOException("Failed to read keyIv, expected " + keyIvLen + " bytes, got " + bytesRead);
                }
                int encKeyLen = (encryptedStream.read() << 24) | (encryptedStream.read() << 16) |
                        (encryptedStream.read() << 8) | encryptedStream.read();
                if (encKeyLen < 0 || encKeyLen > 1024) {
                    throw new IOException("Invalid encryptedDataKey length: " + encKeyLen);
                }
                byte[] encryptedDataKey = new byte[encKeyLen];
                bytesRead = encryptedStream.read(encryptedDataKey);
                if (bytesRead != encKeyLen) {
                    throw new IOException("Failed to read encryptedDataKey, expected " + encKeyLen + " bytes, got " + bytesRead);
                }
                byte[] iv = new byte[Constants.KEY_ENCRYPTION_CTR_IV_LENGTH];
                bytesRead = encryptedStream.read(iv);
                if (bytesRead != Constants.KEY_ENCRYPTION_CTR_IV_LENGTH) {
                    throw new IOException("IV is empty or incomplete: expected " +
                            Constants.KEY_ENCRYPTION_CTR_IV_LENGTH + " bytes, got " + bytesRead);
                }
                logger.log("Part " + index + " - Read keyIv: " + Utils.bytesToHex(keyIv));
                logger.log("Part " + index + " - Read encryptedDataKey: " + Utils.bytesToHex(encryptedDataKey));
                logger.log("Part " + index + " - Read CTR IV: " + Utils.bytesToHex(iv));

                // Decrypt dataKey
                Cipher keyCipher = Cipher.getInstance("AES/GCM/NoPadding");
                SecretKey mskKey = new SecretKeySpec(mskr, "AES");
                byte[] dataKey;
                try {
                    keyCipher.init(Cipher.DECRYPT_MODE, mskKey, new GCMParameterSpec(Constants.GCM_TAG_LENGTH, keyIv));
                    dataKey = keyCipher.doFinal(encryptedDataKey);
                    logger.log("Part " + index + " - Decrypted dataKey: " + Utils.bytesToHex(dataKey));
                } catch (AEADBadTagException e) {
                    logger.log("Part " + index + " - GCM decryption failed: Invalid tag, keyIv=" +
                            Utils.bytesToHex(keyIv) + ", encryptedDataKey=" + Utils.bytesToHex(encryptedDataKey));
                    throw new IOException("GCM decryption failed", e);
                }

                // Decrypt content
                Cipher cipher = Cipher.getInstance(Constants.KEY_ENCRYPTION_CTR_ALGORITHM);
                SecretKey dataKeySpec = new SecretKeySpec(dataKey, Constants.KEY_ENCRYPTION_BASE_ALGORITHM);
                cipher.init(Cipher.DECRYPT_MODE, dataKeySpec, new IvParameterSpec(iv));

                byte[] buffer = new byte[1024];
                while ((bytesRead = encryptedStream.read(buffer)) != -1) {
                    byte[] decryptedData = cipher.update(buffer, 0, bytesRead);
                    System.out.write(decryptedData, 0, decryptedData.length);
                }
                byte[] finalData = cipher.doFinal();
                System.out.write(finalData, 0, finalData.length);
                logger.log("Processed part " + index + " of " + partNum);
            }
        }
        System.out.println();
        Utils.destroyPasskey(mskr);
    }

    public byte[] decryptCTRBigFileToBytes(String sourcePath, byte[] msk) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Cipher keyCipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKey mskKey = new SecretKeySpec(msk, "AES");

        try (InputStream in = new FileInputStream(sourcePath)) {
            // Read header: [keyIv.length (4)][keyIv][encryptedDataKey.length (4)][encryptedDataKey][iv]
            int keyIvLen = (in.read() << 24) | (in.read() << 16) | (in.read() << 8) | in.read();
            if (keyIvLen < 0 || keyIvLen > 1024) {
                throw new IOException("Invalid keyIv length: " + keyIvLen);
            }
            byte[] keyIv = new byte[keyIvLen];
            int bytesRead = in.read(keyIv);
            if (bytesRead != keyIvLen) {
                throw new IOException("Failed to read keyIv, expected " + keyIvLen + " bytes, got " + bytesRead);
            }
            int encKeyLen = (in.read() << 24) | (in.read() << 16) | (in.read() << 8) | in.read();
            if (encKeyLen < 0 || encKeyLen > 1024) {
                throw new IOException("Invalid encryptedDataKey length: " + encKeyLen);
            }
            byte[] encryptedDataKey = new byte[encKeyLen];
            bytesRead = in.read(encryptedDataKey);
            if (bytesRead != encKeyLen) {
                throw new IOException("Failed to read encryptedDataKey, expected " + encKeyLen + " bytes, got " + bytesRead);
            }
            byte[] iv = new byte[Constants.KEY_ENCRYPTION_CTR_IV_LENGTH];
            bytesRead = in.read(iv);
            if (bytesRead != Constants.KEY_ENCRYPTION_CTR_IV_LENGTH) {
                throw new IOException("IV is empty or incomplete: expected " +
                        Constants.KEY_ENCRYPTION_CTR_IV_LENGTH + " bytes, got " + bytesRead);
            }
            logger.log("Read keyIv: " + Utils.bytesToHex(keyIv));
            logger.log("Read encryptedDataKey: " + Utils.bytesToHex(encryptedDataKey));
            logger.log("Read CTR IV: " + Utils.bytesToHex(iv));

            // Decrypt dataKey
            byte[] dataKey;
            try {
                keyCipher.init(Cipher.DECRYPT_MODE, mskKey, new GCMParameterSpec(Constants.GCM_TAG_LENGTH, keyIv));
                dataKey = keyCipher.doFinal(encryptedDataKey);
                logger.log("Decrypted dataKey: " + Utils.bytesToHex(dataKey));
            } catch (AEADBadTagException e) {
                logger.log("GCM decryption failed: Invalid tag, keyIv=" + Utils.bytesToHex(keyIv) +
                        ", encryptedDataKey=" + Utils.bytesToHex(encryptedDataKey));
                throw new IOException("GCM decryption failed", e);
            }

            // Decrypt content
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            SecretKey dataKeySpec = new SecretKeySpec(dataKey, "AES");
            cipher.init(Cipher.DECRYPT_MODE, dataKeySpec, new IvParameterSpec(iv));

            byte[] buffer = new byte[1024 * 1024];
            int index;
            while ((index = in.read(buffer)) != -1) {
                byte[] dec = cipher.update(buffer, 0, index);
                baos.write(dec);
            }
            byte[] dec = cipher.doFinal();
            baos.write(dec);
        }
        byte[] decryptedData = baos.toByteArray();
        logger.log("Decrypted data length: " + decryptedData.length);
        return decryptedData;
    }

    public byte[] viewDecrypted(String userID, String passphrase, String bucketName, String key1, String key0)
            throws Exception {
        logger.log("[" + userID + "] Decrypt and View Started Initiating file decryption");

        try {
            byte[] decryptedData = viewSecureFile(userID, passphrase, bucketName, key1, key0);
            logger.log("[" + userID + "] Decrypt and View Completed File decrypted and sent successfully");
            return decryptedData;
        } catch (Exception e) {
            logger.log("[" + userID + "] Decrypt and View Failed: " + e.getMessage());
            throw new Exception("Failed to decrypt and view: " + e.getMessage(), e);
        }
    }

    private byte[] viewDecryptedOptimization(String passphrase, String key1, String key0, String encryptedFilePathPrefix, int partNum) throws Exception {
        byte[] mskr = take(userID, passphrase, bucketName, key1, key0);
        if (mskr == null) {
            throw new Exception("Failed to retrieve key for user " + userID);
        }

        ByteArrayOutputStream decryptedStream = new ByteArrayOutputStream();
        for (int index = 1; index <= partNum; index++) {
            String encryptedPartPath = encryptedFilePathPrefix + "Part" + index;
            byte[] partContent = decryptCTRBigFileToBytes(encryptedPartPath, mskr);
            decryptedStream.write(partContent);
            if (verbose) logger.log("Processed part " + index + " of " + partNum);
        }

        Utils.destroyPasskey(mskr);
        return decryptedStream.toByteArray();
    }
}
