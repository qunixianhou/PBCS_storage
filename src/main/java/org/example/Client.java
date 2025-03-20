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
    // 修改构造函数，支持传入 userID
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
        this.userID = userID; // 使用用户提供的 userID
        this.secureRetFilePath = Constants.FILE_PATH + userID + "/secureRetrieve";
        this.internalCipherFilePath = Constants.FILE_PATH + userID + "/internal";
        this.plainFilePath = Constants.FILE_PATH + userID + "/plain";
        this.optSecureRetFilePath = Constants.FILE_PATH + userID + "/optSecureRetrieve";
        this.encryptionFilePath = Constants.FILE_PATH + userID + "/encryption";
        this.decryptionFilePath = Constants.FILE_PATH + userID + "/decryption";
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
    // 修改 start 方法，接受 passphrase 参数
    public void start(String sourceFilePath, String passphrase) throws Exception {
        String key0 = userID + "/sid";
        String key1 = userID + "/rid";
        String key2 = userID + "/optimizedEncryptedFile";
        String key3 = userID + "/plainFile";
        String key4 = userID + "/oneThreadEncryptedFile";

        byte[] msk, mskr;
        int partNum;
        String hardenedPWD, hardenedPWD1;

        // 1. 密码硬化
        if (verbose) logger.log("PASSWORD HARDENING PROTOCOL");
        hardenedPWD = ibOPRF(userID, passphrase);

        // 2. 如果已注册，跳过注册步骤
        if (! AuthServer.getInstance().isUserRegistered(userID)) {
            register(userID, passphrase, bucketName, key0);
        }

        // 3. 再次密码硬化
        if (verbose) logger.log("PASSWORD HARDENING PROTOCOL");
        hardenedPWD = ibOPRF(userID, passphrase);

        // 4. 密钥存款
        if (verbose) logger.log("KEY DEPOSIT PROTOCOL");
        msk = give(userID, passphrase, bucketName, key1, key0);

        // 5. 加密并上传文件（优化版本）
        if (verbose) logger.log("ENCRYPT AND UPLOAD FILE");
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
        if (verbose) logger.log("RETRIEVE ENCRYPTED FILE");
        secureRetrieveOptimization(partNum, bucketName, key2, optSecureRetFilePath);

        // 9. 加密并上传文件（单线程版本）
        if (verbose) logger.log("ENCRYPT AND UPLOAD FILE");
        secureDeposit(bucketName, key4, msk, sourceFilePath, internalCipherFilePath + "singleThreadEncryptedFile");

        // 10. 下载加密文件（单线程版本）
        if (verbose) logger.log("RETRIEVE ENCRYPTED FILE");
        secureRetrieve(bucketName, key4, secureRetFilePath);

        // 11. 上传明文文件
        if (verbose) logger.log("UPLOAD PLAIN FILE\n");
        depositPlainFile(bucketName, key3, sourceFilePath);

        // 12. 检索明文文件
        if (verbose) logger.log("RETRIEVE PLAIN FILE");
        retrievePlainBigFile(bucketName, key3, plainFilePath);

        // 13. 加密明文文件
        if (verbose) logger.log("Encrypt PLAIN FILE");
        encryptCTRBigFile(sourceFilePath, encryptionFilePath, msk);

        // 14. 解密密文文件
        if (verbose) logger.log("Decrypt CT FILE");
        decryptCTRBigFile(encryptionFilePath, decryptionFilePath, mskr);

        // 15. 检查硬化密码一致性
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

        {
            try {
                final LocalS3Client s3 = LocalS3Client.Builder.standard().withBaseDirectory(this.localS3Path).build();
                s3.putObject(new LocalS3Client.PutObjectRequest(bucketName, key1, createFileFromByte(parameter)));
                LocalS3Client.S3Object object = s3.getObject(new LocalS3Client.GetObjectRequest(bucketName, key0));
                sid = IOUtils.toByteArray(object.getObjectContent());
            } catch (Exception e) {
                System.out.println("Caught an AmazonServiceException: " + e.getMessage());
                throw e;
            }
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

    public void depositPlainFile(String bucketName, String key3, String sourceFilePath) {
        try {
            final LocalS3Client s3 = LocalS3Client.Builder.standard()
                    .withBaseDirectory(this.localS3Path)
                    .build();
            s3.setBucketAccelerateConfiguration(new LocalS3Client.SetBucketAccelerateConfigurationRequest(bucketName,
                    new LocalS3Client.BucketAccelerateConfiguration("Enabled")));
            s3.putObject(new LocalS3Client.PutObjectRequest(bucketName, key3, new File(sourceFilePath)));
        } catch (Exception e) {
            System.out.println("Error in local S3 operation: " + e.getMessage());
            throw e;
        }
    }

    public void retrievePlainBigFile(String bucketName, String key3, String plainFilePath) throws IOException {
        try {
            final LocalS3Client s3 = LocalS3Client.Builder.standard()
                    .withBaseDirectory(this.localS3Path)
                    .build();
            s3.setBucketAccelerateConfiguration(new LocalS3Client.SetBucketAccelerateConfigurationRequest(bucketName,
                    new LocalS3Client.BucketAccelerateConfiguration("Enabled")));
            LocalS3Client.S3Object object = s3.getObject(new LocalS3Client.GetObjectRequest(bucketName, key3));
            InputStream s3is = object.getObjectContent();
            FileOutputStream fos = new FileOutputStream(plainFilePath);
            byte[] read_buf = new byte[1024];
            int read_len = 0;
            while ((read_len = s3is.read(read_buf)) != -1) {
                fos.write(read_buf, 0, read_len);
            }
            s3is.close();
            fos.close();
        } catch (Exception e) {
            System.out.println("Error in local S3 operation: " + e.getMessage());
            throw e instanceof IOException ? (IOException) e : new IOException(e);
        }
    }

    public void secureDeposit(String bucketName, String key2, byte[] sKey, String sourceFilePath, String internalCipherFilePath)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
        try {
            encryptCTRBigFile(sourceFilePath, internalCipherFilePath, sKey);
            final LocalS3Client s3 = LocalS3Client.Builder.standard()
                    .withBaseDirectory(this.localS3Path)
                    .build();
            s3.setBucketAccelerateConfiguration(new LocalS3Client.SetBucketAccelerateConfigurationRequest(bucketName,
                    new LocalS3Client.BucketAccelerateConfiguration("Enabled")));
            s3.putObject(new LocalS3Client.PutObjectRequest(bucketName, key2, new File(internalCipherFilePath)));
        } catch (Exception e) {
            System.out.println("Error in local S3 operation: " + e.getMessage());
            throw e;
        }
    }

    public void encryptCTRBigFile(String sourcePath, String desPath, byte[] key)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
        try {
            Cipher cipher = Cipher.getInstance(Constants.KEY_ENCRYPTION_CTR_ALGORITHM);
            SecretKey keyEncryptionKey = new SecretKeySpec(key, Constants.KEY_ENCRYPTION_BASE_ALGORITHM);
            SecureRandom secureRandom = new SecureRandom();
            byte[] iv = new byte[Constants.KEY_ENCRYPTION_CTR_IV_LENGTH];
            secureRandom.nextBytes(iv);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            cipher.init(Cipher.ENCRYPT_MODE, keyEncryptionKey, ivParameterSpec);

            byte[] buffer = new byte[1024 * 1024];
            InputStream in = new FileInputStream(sourcePath);

            ensureDirectoryExists(desPath);
            OutputStream out = new FileOutputStream(desPath);

            int index;
            out.write(iv);
            while ((index = in.read(buffer)) != -1) {
                byte[] enc = cipher.update(buffer, 0, index);
                out.write(enc);
            }
            byte[] enc = cipher.doFinal();
            out.write(enc);
            in.close();
            out.close();
        } catch (IOException e) {
            throw new IOException("Failed to encrypt file to " + desPath, e);
        }
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

            LocalS3Client.S3Object object = s3.getObject(new LocalS3Client.GetObjectRequest(bucketName, key2));
            InputStream s3is = object.getObjectContent();

            ensureDirectoryExists(encryptedFilePath);
            try (FileOutputStream fos = new FileOutputStream(encryptedFilePath)) {
                byte[] buffer = new byte[1024];
                int bytesRead;
                int totalBytes = 0;
                while ((bytesRead = s3is.read(buffer)) != -1) {
                    fos.write(buffer, 0, bytesRead);
                    totalBytes += bytesRead;
                }
                if (verbose) {
                    logger.log("Encrypted file downloaded, " + totalBytes + " bytes saved to " + encryptedFilePath);
                }
            }
            s3is.close();
        } catch (Exception e) {
            logger.log("Error in secureRetrieve", "Failed to retrieve file: " + e.getMessage());
            throw e instanceof IOException ? (IOException) e : new IOException(e);
        }
    }

    public void secureRetrieveOptimization(int partNum, String bucketName, String key2, String encryptedFilePathPrefix) throws IOException {
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
                LocalS3Client.S3Object object = s3.getObject(new LocalS3Client.GetObjectRequest(bucketName, partKey));
                try (InputStream s3is = object.getObjectContent();
                     FileOutputStream fos = new FileOutputStream(encryptedPartPath)) {
                    byte[] buffer = new byte[1024];
                    int bytesRead;
                    while ((bytesRead = s3is.read(buffer)) != -1) {
                        fos.write(buffer, 0, bytesRead);
                    }
                }
                if (verbose) {
                    logger.log("Encrypted file part " + index + " saved to " + encryptedPartPath);
                }
            }
        } catch (Exception e) {
            System.out.println("Error in local S3 operation: " + e.getMessage());
            throw e instanceof IOException ? (IOException) e : new IOException(e);
        }
    }

    public int secureDepositOptimization(String bucketName, String key2, byte[] sKey, String sourceFilePath) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
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
        Thread threadEnc = new EncThread(encList, partNumber, partSize, sourceFilePath, internalCipherFilePath, sKey);
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

    public static void decryptCTRBigFile(String sourcePath, String desPath, byte[] key)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
        byte[] buffer = new byte[1024 * 1024];
        InputStream in = new FileInputStream(sourcePath);
        OutputStream out = new FileOutputStream(desPath);
        byte[] iv = new byte[Constants.KEY_ENCRYPTION_CTR_IV_LENGTH];
        in.read(iv);

        Cipher cipher = Cipher.getInstance(Constants.KEY_ENCRYPTION_CTR_ALGORITHM);
        SecretKey keyEncryptionKey = new SecretKeySpec(key, Constants.KEY_ENCRYPTION_BASE_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keyEncryptionKey, new IvParameterSpec(iv));

        int index;
        while ((index = in.read(buffer)) != -1) {
            byte[] dec = cipher.update(buffer, 0, index);
            out.write(dec);
        }
        byte[] dec = cipher.doFinal();
        out.write(dec);
        in.close();
        out.close();
    }
    public void view(String passphrase) throws Exception {
        String key0 = userID + "/sid";
        String key1 = userID + "/rid";

        // 检查单线程加密文件是否存在
        File secureFile = new File(secureRetFilePath);
        File optSecureFilePart1 = new File(optSecureRetFilePath + "Part1");

        if (secureFile.exists()) {
            if (verbose) logger.log("Viewing single-threaded encrypted file: " + secureRetFilePath);
            viewSecureFile(userID, passphrase, bucketName, key1, key0, secureRetFilePath);
        } else if (optSecureFilePart1.exists()) {
            // 计算分片数量
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

    // Existing viewSecureFile method (already implemented in your provided code)
    public void viewSecureFile(String userID, String passphrase, String bucketName, String key1, String key0, String encryptedFilePath)
            throws Exception {
        // 1. 获取密钥
        byte[] mskr = take(userID, passphrase, bucketName, key1, key0);
        if (mskr == null) {
            throw new Exception("Failed to retrieve key for user " + userID);
        }

        // 2. 读取并在内存中解密文件
        try (InputStream encryptedStream = new FileInputStream(encryptedFilePath)) {
            Cipher cipher = Cipher.getInstance(Constants.KEY_ENCRYPTION_CTR_ALGORITHM);
            SecretKey keyEncryptionKey = new SecretKeySpec(mskr, Constants.KEY_ENCRYPTION_BASE_ALGORITHM);
            byte[] iv = new byte[Constants.KEY_ENCRYPTION_CTR_IV_LENGTH];
            encryptedStream.read(iv); // 读取 IV
            cipher.init(Cipher.DECRYPT_MODE, keyEncryptionKey, new IvParameterSpec(iv));

            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = encryptedStream.read(buffer)) != -1) {
                byte[] decryptedData = cipher.update(buffer, 0, bytesRead);
                System.out.write(decryptedData, 0, decryptedData.length);
            }
            byte[] finalData = cipher.doFinal();
            System.out.write(finalData, 0, finalData.length);
            System.out.println(); // 换行
        }

        // 3. 清理密钥
        Utils.destroyPasskey(mskr);
    }

    // Existing viewSecureFileOptimization method (already implemented in your provided code)
    public void viewSecureFileOptimization(String userID, String passphrase, String bucketName, String key1, String key0,
                                           String encryptedFilePathPrefix, int partNum)
            throws Exception {
        // 1. 获取密钥
        byte[] mskr = take(userID, passphrase, bucketName, key1, key0);
        if (mskr == null) {
            throw new Exception("Failed to retrieve key for user " + userID);
        }

        // 2. 依次读取并解密每个分片
        if (verbose) {
            logger.log("Viewing secure file parts from " + encryptedFilePathPrefix);
        }
        for (int index = 1; index <= partNum; index++) {
            String encryptedPartPath = encryptedFilePathPrefix + "Part" + index;
            try (InputStream encryptedStream = new FileInputStream(encryptedPartPath)) {
                Cipher cipher = Cipher.getInstance(Constants.KEY_ENCRYPTION_CTR_ALGORITHM);
                SecretKey keyEncryptionKey = new SecretKeySpec(mskr, Constants.KEY_ENCRYPTION_BASE_ALGORITHM);
                byte[] iv = new byte[Constants.KEY_ENCRYPTION_CTR_IV_LENGTH];
                encryptedStream.read(iv); // 读取 IV
                cipher.init(Cipher.DECRYPT_MODE, keyEncryptionKey, new IvParameterSpec(iv));

                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = encryptedStream.read(buffer)) != -1) {
                    byte[] decryptedData = cipher.update(buffer, 0, bytesRead);
                    System.out.write(decryptedData, 0, decryptedData.length);
                }
                byte[] finalData = cipher.doFinal();
                System.out.write(finalData, 0, finalData.length);
            }
            if (verbose) {
                logger.log("Processed part " + index + " of " + partNum);
            }
        }
        System.out.println(); // 换行

        // 3. 清理密钥
        Utils.destroyPasskey(mskr);
    }
    public byte[] decryptCTRBigFileToBytes(String sourcePath, byte[] key) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Cipher cipher = Cipher.getInstance(Constants.KEY_ENCRYPTION_CTR_ALGORITHM);
        SecretKey keyEncryptionKey = new SecretKeySpec(key, Constants.KEY_ENCRYPTION_BASE_ALGORITHM);
        try (InputStream in = new FileInputStream(sourcePath)) {
            byte[] iv = new byte[Constants.KEY_ENCRYPTION_CTR_IV_LENGTH];
            in.read(iv);
            cipher.init(Cipher.DECRYPT_MODE, keyEncryptionKey, new IvParameterSpec(iv));
            byte[] buffer = new byte[1024 * 1024];
            int index;
            while ((index = in.read(buffer)) != -1) {
                byte[] dec = cipher.update(buffer, 0, index);
                baos.write(dec);
            }
            byte[] dec = cipher.doFinal();
            baos.write(dec);
        }
        return baos.toByteArray();
    }
    public byte[] viewDecrypted(String passphrase) throws Exception {
        String key0 = userID + "/sid";
        String key1 = userID + "/rid";

        // 检查单线程加密文件或分片文件是否存在
        File secureFile = new File(secureRetFilePath);
        File optSecureFilePart1 = new File(optSecureRetFilePath + "Part1");

        if (secureFile.exists()) {
            if (verbose) logger.log("Viewing single-threaded encrypted file: " + secureRetFilePath);
            return decryptCTRBigFileToBytes(secureRetFilePath, take(userID, passphrase, bucketName, key1, key0));
        } else if (optSecureFilePart1.exists()) {
            // 计算分片数量
            int partNum = 0;
            while (new File(optSecureRetFilePath + "Part" + (partNum + 1)).exists()) {
                partNum++;
            }
            if (partNum == 0) {
                throw new Exception("No parts found for encrypted file prefix: " + optSecureRetFilePath);
            }
            if (verbose) logger.log("Detected " + partNum + " parts for encrypted file: " + optSecureRetFilePath);
            return viewDecryptedOptimization(passphrase, key1, key0, optSecureFilePart1.getParent(), partNum);
        } else {
            throw new Exception("No encrypted files found for user ID: " + userID);
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