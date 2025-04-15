package org.example;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

public class EncThread extends Thread {
    private final int partNum;
    private final int partSize;
    private final String sourcePath;
    private final String destPath;
    private final byte[][] dataKeys;
    private final byte[][] encryptedDataKeys;
    private final byte[][] keyIvs;
    private final List<Integer> indexList;
    private final Client.Logger logger;

    public EncThread(List<Integer> indexList, int partNum, int partSize, String sourcePath, String destPath,
                     byte[][] dataKeys, byte[][] encryptedDataKeys, byte[][] keyIvs) {
        this.indexList = indexList;
        this.partNum = partNum;
        this.partSize = partSize;
        this.sourcePath = sourcePath;
        this.destPath = destPath;
        this.dataKeys = dataKeys;
        this.encryptedDataKeys = encryptedDataKeys;
        this.keyIvs = keyIvs;
        this.logger = new Client.Logger() {
            @Override
            public void log(String message) {
                System.out.println(message);
            }
            @Override
            public void log(String tag, String message) {
                log(tag + ": " + message);
            }
        };
    }

    @Override
    public void run() {
        try {
            encryptFilePart(partNum, partSize, sourcePath, destPath, dataKeys[partNum - 1],
                    encryptedDataKeys[partNum - 1], keyIvs[partNum - 1]);
            indexList.add(partNum);
            logger.log("Encryption completed for part " + partNum + " at " + destPath + "EncPart" + partNum);
        } catch (Exception e) {
            logger.log("EncThread Error", "Failed to encrypt file part " + partNum + ": " + e.getMessage());
            throw new RuntimeException("Encryption failed for part " + partNum, e);
        }
    }

    private void encryptFilePart(int partNum, int partSize, String sourcePath, String destPath, byte[] dataKey,
                                 byte[] encryptedDataKey, byte[] keyIv)
            throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(Constants.KEY_ENCRYPTION_CTR_ALGORITHM);
        SecretKey keyEncryptionKey = new SecretKeySpec(dataKey, Constants.KEY_ENCRYPTION_BASE_ALGORITHM);
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[Constants.KEY_ENCRYPTION_CTR_IV_LENGTH];
        secureRandom.nextBytes(iv);
        IvParameterSpec parameterSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, keyEncryptionKey, parameterSpec);

        long offset = (long) (partNum - 1) * partSize;
        String outputFilePath = destPath + "EncPart" + partNum;
        logger.log("Encrypting file part to: " + outputFilePath);

        File outputFile = new File(outputFilePath);
        File parentDir = outputFile.getParentFile();
        if (parentDir != null && !parentDir.exists()) {
            logger.log("Creating directory: " + parentDir.getAbsolutePath());
            boolean created = parentDir.mkdirs();
            if (!created) {
                throw new IOException("Failed to create directory: " + parentDir.getAbsolutePath());
            }
        }

        try (InputStream in = new FileInputStream(sourcePath);
             OutputStream out = new FileOutputStream(outputFilePath)) {
            long skipped = in.skip(offset);
            if (skipped != offset) {
                throw new IOException("Failed to skip to offset " + offset + ", skipped " + skipped);
            }

            byte[] buffer = new byte[partSize];
            int bytesRead = in.read(buffer);
            if (bytesRead <= 0) {
                throw new IOException("No data read for part " + partNum);
            }

            // 写入加密的数据密钥和其 IV
            out.write(keyIv.length);
            out.write(keyIv);
            out.write(encryptedDataKey.length);
            out.write(encryptedDataKey);

            // 写入文件 IV 和加密数据
            out.write(iv);
            byte[] dataToEncrypt = (bytesRead < partSize) ? Arrays.copyOf(buffer, bytesRead) : buffer;
            byte[] encryptedData = cipher.doFinal(dataToEncrypt);
            out.write(encryptedData);
        }
    }
}