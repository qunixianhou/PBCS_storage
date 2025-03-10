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
    private final int partNum; // 分片编号（从 1 开始）
    private final int partSize; // 每片大小
    private final String sourcePath; // 输入文件路径
    private final String destPath; // 输出文件路径前缀
    private final byte[] key; // 加密密钥
    private final List<Integer> indexList; // 已完成的分片索引
    private final Client.Logger logger; // 日志记录器

    // 构造函数
    public EncThread(List<Integer> indexList, int partNum, int partSize, String sourcePath, String destPath, byte[] key) {
        this.indexList = indexList;
        this.partNum = partNum;
        this.partSize = partSize;
        this.sourcePath = sourcePath;
        this.destPath = destPath;
        this.key = Arrays.copyOf(key, key.length); // 防御性拷贝
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
            encryptFilePart(partNum, partSize, sourcePath, destPath, key);
            indexList.add(partNum); // 成功后记录分片索引
        } catch (Exception e) {
            logger.log("EncThread Error", "Failed to encrypt file part " + partNum + ": " + e.getMessage());
            throw new RuntimeException("Encryption failed for part " + partNum, e);
        }
    }

    private void encryptFilePart(int partNum, int partSize, String sourcePath, String destPath, byte[] key)
            throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(Constants.KEY_ENCRYPTION_CTR_ALGORITHM);
        SecretKey keyEncryptionKey = new SecretKeySpec(key, Constants.KEY_ENCRYPTION_BASE_ALGORITHM);
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[Constants.KEY_ENCRYPTION_CTR_IV_LENGTH];
        secureRandom.nextBytes(iv);
        IvParameterSpec parameterSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, keyEncryptionKey, parameterSpec);

        // 计算分片偏移
        long offset = (long) (partNum - 1) * partSize;
        String outputFilePath = destPath + "EncPart" + partNum;
        logger.log("Encrypting file part to: " + outputFilePath);

        // 确保输出目录存在
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
            // 跳到分片起始位置
            long skipped = in.skip(offset);
            if (skipped != offset) {
                throw new IOException("Failed to skip to offset " + offset + ", skipped " + skipped);
            }

            byte[] buffer = new byte[partSize];
            int bytesRead = in.read(buffer);
            if (bytesRead <= 0) {
                throw new IOException("No data read for part " + partNum);
            }

            // 处理分片数据
            byte[] dataToEncrypt = (bytesRead < partSize) ? Arrays.copyOf(buffer, bytesRead) : buffer;
            byte[] encryptedData = cipher.doFinal(dataToEncrypt);

            // 写入 IV 和加密数据
            out.write(iv);
            out.write(encryptedData);
        }
    }
}