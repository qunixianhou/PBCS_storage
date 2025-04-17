package org.example;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.SecureRandom;
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
        for (int i = 0; i < partNum; i++) {
            String partPath = destPath + "EncPart" + (i + 1);
            try (FileInputStream in = new FileInputStream(sourcePath);
                 FileOutputStream out = new FileOutputStream(partPath)) {
                // Skip to the correct offset
                long offset = (long) i * partSize;
                long skipped = in.skip(offset);
                if (skipped != offset) {
                    throw new IOException("Failed to skip to offset " + offset + ", skipped " + skipped);
                }

                // Get encryption parameters
                byte[] dataKey = dataKeys[i];
                byte[] encryptedDataKey = encryptedDataKeys[i];
                byte[] keyIv = keyIvs[i];
                byte[] iv = new byte[Constants.KEY_ENCRYPTION_CTR_IV_LENGTH];
                SecureRandom.getInstanceStrong().nextBytes(iv);

                // Log encryption parameters
                logger.log("Part " + (i + 1) + " - Generated dataKey: " + Utils.bytesToHex(dataKey));
                logger.log("Part " + (i + 1) + " - Key IV (GCM): " + Utils.bytesToHex(keyIv));
                logger.log("Part " + (i + 1) + " - Encrypted dataKey: " + Utils.bytesToHex(encryptedDataKey));
                logger.log("Part " + (i + 1) + " - CTR IV: " + Utils.bytesToHex(iv));

                // Write header: [keyIv.length (4)][keyIv][encryptedDataKey.length (4)][encryptedDataKey][iv]
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
                Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(dataKey, "AES"), new IvParameterSpec(iv));
                byte[] buffer = new byte[8192];
                int bytesRead;
                int totalRead = 0;
                while (totalRead < partSize && (bytesRead = in.read(buffer)) != -1) {
                    int toRead = Math.min(bytesRead, partSize - totalRead);
                    byte[] encrypted = cipher.update(buffer, 0, toRead);
                    if (encrypted != null) {
                        out.write(encrypted);
                    }
                    totalRead += toRead;
                }
                byte[] finalBlock = cipher.doFinal();
                if (finalBlock != null) {
                    out.write(finalBlock);
                }
                logger.log("Encrypted file part to: " + partPath);
                indexList.add(i + 1);
            } catch (Exception e) {
                logger.log("Encryption failed for part " + (i + 1) + ": " + e.getMessage());
            }
        }
    }
}
