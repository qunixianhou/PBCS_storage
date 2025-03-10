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
    private final String userID; // 添加 userID 字段

    private static String internalCipherFilePath = Constants.FILE_PATH + "internal";
    private static String plainFilePath = Constants.FILE_PATH + "plain";
    private static String secureRetFilePath = Constants.FILE_PATH + "secureRetrieve";
    private static String optSecureRetFilePath = Constants.FILE_PATH + "optSecureRetrieve";
    private static String decryptionFilePath = Constants.FILE_PATH + "decryption";
    private static String encryptionFilePath;
    private static String getUserFilePath(String basePath, String userID) {
        return basePath + File.separator + userID;
    }
    SimpleEcCurve curve = new SimpleEcCurve(Constants.CURVE_NAME);

    public interface Logger {
        void log(String tag, String message);
        void log(String message);
    }

    public Client(String bucketName, String localS3Path) {
        this(SocketFactory.getDefault(), new Logger() {
            @Override
            public void log(String message) {
                System.out.println(message);
            }
            @Override
            public void log(String tag, String message) {
                log(tag + ": " + message);
            }
        }, Constants.KDF_HASH_REPETITIONS, bucketName, localS3Path);
    }

    public Client(SocketFactory socketFactory, Logger logger, int kdmHashRepetitions, String bucketName, String localS3Path) {
        this.socketFactory = socketFactory;
        this.logger = logger;
        this.kdfHashRepetitions = kdmHashRepetitions;
        this.bucketName = bucketName;
        this.localS3Path = localS3Path;
        // 初始化 userID
        byte[] randomBytes = new byte[10];
        new Random().nextBytes(randomBytes);
        this.userID = "username" + Utils.bytesToHex(randomBytes);
        // 动态生成文件路径
        internalCipherFilePath = Constants.FILE_PATH + userID + "/internal";
        plainFilePath = Constants.FILE_PATH + userID + "/plain";
        secureRetFilePath = Constants.FILE_PATH + userID + "/secureRetrieve";
        optSecureRetFilePath = Constants.FILE_PATH + userID + "/optSecureRetrieve";
        encryptionFilePath = Constants.FILE_PATH + userID + "/encryption";
        decryptionFilePath = Constants.FILE_PATH + userID + "/decryption";

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
    public void start(String sourceFilePath) throws Exception {
        byte[] randomBytes = new byte[10];
        Random rand = new Random();
        rand.nextBytes(randomBytes);
        String passphrase = "passphrase" + Utils.bytesToHex(randomBytes);
        String key0 = userID + "/sid";
        String key1 = userID + "/rid";
        String key2 = userID + "/optimizedEncryptedFile";
        String key3 = userID + "/plianFile";
        String key4 = userID + "/oneThreadEncryptedFile";

        byte[] msk, mskr;
        int partNum;
        String hardenedPWD, hardenedPWD1;

        // 1. 密码硬化
        try {
            if (verbose) logger.log("PASSWORD HARDENING PROTOCOL");
            hardenedPWD = ibOPRF(userID, passphrase);
        } catch (Exception e) {
            logger.log("Error in password hardening", e.getMessage());
            throw new Exception("Password hardening failed", e);
        }

        // 2. 注册
        try {
            register(userID, passphrase, bucketName, key0);
        } catch (Exception e) {
            logger.log("Error in registration", e.getMessage());
            throw new Exception("Registration failed", e);
        }

        // 3. 再次密码硬化
        try {
            if (verbose) logger.log("PASSWORD HARDENING PROTOCOL");
            hardenedPWD = ibOPRF(userID, passphrase);
        } catch (Exception e) {
            logger.log("Error in second password hardening", e.getMessage());
            throw new Exception("Second password hardening failed", e);
        }

        // 4. 密钥存款
        try {
            if (verbose) logger.log("KEY DEPOSIT PROTOCOL");
            msk = give(userID, passphrase, bucketName, key1, key0);
        } catch (Exception e) {
            logger.log("Error in key deposit", e.getMessage());
            throw new Exception("Key deposit failed", e);
        }

        // 5. 加密并上传文件（优化版本）
        try {
            if (verbose) logger.log("ENCRYPT AND UPLOAD FILE");
            partNum = secureDepositOptimization(bucketName, key2, msk, sourceFilePath);
        } catch (Exception e) {
            logger.log("Error in optimized file encryption/upload", e.getMessage());
            throw new Exception("Optimized file encryption/upload failed", e);
        }

        // 6. 再次密码硬化
        try {
            if (verbose) logger.log("PASSWORD HARDENING PROTOCOL");
            hardenedPWD1 = ibOPRF(userID, passphrase);
        } catch (Exception e) {
            logger.log("Error in third password hardening", e.getMessage());
            throw new Exception("Third password hardening failed", e);
        }

        // 7. 密钥检索
        try {
            if (verbose) logger.log("KEY RETRIEVAL PROTOCOL\n");
            mskr = take(userID, passphrase, bucketName, key1, key0);
            if (!Arrays.equals(msk, mskr)) {
                throw new Exception("msk does not match mskr");
            }
        } catch (Exception e) {
            logger.log("Error in key retrieval", e.getMessage());
            throw new Exception("Key retrieval failed", e);
        }

        // 8. 检索并解密文件（优化版本）
        try {
            if (verbose) logger.log("RETRIEVE AND DEC FILE");
            secureRetrieveOptimization(partNum, bucketName, key2, mskr, optSecureRetFilePath);
        } catch (Exception e) {
            logger.log("Error in optimized file retrieval/decryption", e.getMessage());
            throw new Exception("Optimized file retrieval/decryption failed", e);
        }

        // 9. 加密并上传文件（单线程版本）
        try {
            if (verbose) logger.log("ENCRYPT AND UPLOAD FILE");
            secureDeposit(bucketName, key4, msk, sourceFilePath, internalCipherFilePath);
        } catch (Exception e) {
            logger.log("Error in single-thread file encryption/upload", e.getMessage());
            throw new Exception("Single-thread file encryption/upload failed", e);
        }

        // 10. 检索并解密文件（单线程版本）
        try {
            if (verbose) logger.log("RETRIEVE AND DEC FILE\n");
            secureRetrieve(bucketName, key4, mskr, secureRetFilePath);
        } catch (Exception e) {
            logger.log("Error in single-thread file retrieval/decryption", e.getMessage());
            throw new Exception("Single-thread file retrieval/decryption failed", e);
        }

        // 11. 上传明文文件
        try {
            if (verbose) logger.log("UPLOAD PLAIN FILE\n");
            depositPlainFile(bucketName, key3, sourceFilePath);
        } catch (Exception e) {
            logger.log("Error in plain file upload", e.getMessage());
            throw new Exception("Plain file upload failed", e);
        }

        // 12. 检索明文文件
        try {
            if (verbose) logger.log("RETRIEVE PLAIN FILE");
            retrievePlainBigFile(bucketName, key3, plainFilePath);
        } catch (Exception e) {
            logger.log("Error in plain file retrieval", e.getMessage());
            throw new Exception("Plain file retrieval failed", e);
        }

        // 13. 加密明文文件
        try {
            if (verbose) logger.log("Encrypt PLAIN FILE");
            encryptCTRBigFile(sourceFilePath, encryptionFilePath, msk);
        } catch (Exception e) {
            logger.log("Error in plain file encryption", e.getMessage());
            throw new Exception("Plain file encryption failed", e);
        }

        // 14. 解密密文文件
        try {
            if (verbose) logger.log("Decrypt CT FILE");
            decryptCTRBigFile(encryptionFilePath, decryptionFilePath, mskr);
        } catch (Exception e) {
            logger.log("Error in ciphertext decryption", e.getMessage());
            throw new Exception("Ciphertext decryption failed", e);
        }

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

    public void secureRetrieve(String bucketName, String key2, byte[] sKey, String desPath)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
        if (verbose) {
            System.out.format("Retrieving from S3 bucket %s...\n", bucketName);
        }
        try {
            final LocalS3Client s3 = LocalS3Client.Builder.standard()
                    .withBaseDirectory(this.localS3Path)
                    .build();
            s3.setBucketAccelerateConfiguration(new LocalS3Client.SetBucketAccelerateConfigurationRequest(bucketName,
                    new LocalS3Client.BucketAccelerateConfiguration("Enabled")));

            if (verbose) {
                System.out.println("Retrieve File from bucket " + bucketName);
                System.out.println("Retrieve parameter\n");
            }

            LocalS3Client.S3Object object = s3.getObject(new LocalS3Client.GetObjectRequest(bucketName, key2));
            InputStream s3is = object.getObjectContent();

            byte[] iv = new byte[Constants.KEY_ENCRYPTION_CTR_IV_LENGTH];
            s3is.read(iv);
            Cipher cipher = Cipher.getInstance(Constants.KEY_ENCRYPTION_CTR_ALGORITHM);
            SecretKey keyEncryptionKey = new SecretKeySpec(sKey, Constants.KEY_ENCRYPTION_BASE_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, keyEncryptionKey, new IvParameterSpec(iv));

            // 调用 ensureDirectoryExists 确保目录存在
            ensureDirectoryExists(desPath);
            FileOutputStream fos = new FileOutputStream(desPath);

            int index;
            byte[] buffer = new byte[1024];
            while ((index = s3is.read(buffer)) != -1) {
                byte[] dec = cipher.update(buffer, 0, index);
                fos.write(dec);
            }
            byte[] dec = cipher.doFinal();
            fos.write(dec);
            s3is.close();
            fos.close();
        } catch (Exception e) {
            System.out.println("Error in local S3 operation: " + e.getMessage());
            throw e;
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

    public void secureRetrieveOptimization(int partNum, String bucketName, String key2, byte[] sKey, String desPath) throws IOException {
        List<InputStream> decList = new CopyOnWriteArrayList<>();
        if (verbose) {
            System.out.format("Retrieving from S3 bucket %s...\n", bucketName);
        }
        try {
            final LocalS3Client s3 = LocalS3Client.Builder.standard()
                    .withBaseDirectory(this.localS3Path)
                    .build();
            s3.setBucketAccelerateConfiguration(new LocalS3Client.SetBucketAccelerateConfigurationRequest(bucketName,
                    new LocalS3Client.BucketAccelerateConfiguration("Enabled")));

            Thread decThread = new StreamDecThread(decList, internalCipherFilePath, desPath, sKey, partNum);
            decThread.start();
            int index = 0;
            InputStream[] s3isset = new InputStream[partNum];
            while (index < partNum) {
                index++;
                String partKey = key2 + "/part" + index;
                LocalS3Client.S3Object object = s3.getObject(new LocalS3Client.GetObjectRequest(bucketName, partKey));
                s3isset[index - 1] = object.getObjectContent();
                decList.add(s3isset[index - 1]);
            }
            try {
                decThread.join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            for (int i = 0; i < partNum; i++) {
                s3isset[i].close();
            }
        } catch (Exception e) {
            System.out.println("Error in local S3 operation: " + e.getMessage());
            throw e instanceof IOException ? (IOException) e : new IOException(e);
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
}