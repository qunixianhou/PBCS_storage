package org.example;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

public class StreamDecThread extends Thread {
    private final List<InputStream> list; // 实例字段
    private final String sourceInterPath;
    private final String desPath;
    private final byte[] key;
    private final int partNum;

    public StreamDecThread(List<InputStream> decList, String sourceInterPath, String desPath, byte[] key, int partNum) {
        this.list = decList;
        this.sourceInterPath = sourceInterPath;
        this.desPath = desPath;
        this.key = key;
        this.partNum = partNum;
    }

    public void run() {
        try {
            decryptStreamCTRCombine(sourceInterPath, desPath, key, partNum);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | BadPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException | NoSuchPaddingException | IOException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }

    public void decryptStreamCTRCombine(String sourceInterPath, String desPath, byte[] key, int partNum)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException, IOException {
        int index = 0;
        Cipher cipher = Cipher.getInstance(Constants.KEY_ENCRYPTION_CTR_ALGORITHM);
        SecretKey keyEncryptionKey = new SecretKeySpec(key, Constants.KEY_ENCRYPTION_BASE_ALGORITHM);

        // 确保目录存在
        File file = new File(desPath);
        File parentDir = file.getParentFile();
        if (parentDir != null && !parentDir.exists()) {
            parentDir.mkdirs();
        }

        try (FileOutputStream fileOutputStream = new FileOutputStream(desPath, true)) {
            while (index < partNum) {
                index++;
                while (list.size() < index) ;
                try (InputStream input = list.get(index - 1)) {
                    byte[] iv = new byte[Constants.KEY_ENCRYPTION_CTR_IV_LENGTH];
                    input.read(iv);
                    cipher.init(Cipher.DECRYPT_MODE, keyEncryptionKey, new IvParameterSpec(iv));
                    byte[] read_buf = new byte[1024];
                    int read_len;
                    while ((read_len = input.read(read_buf)) > 0) {
                        byte[] dec = cipher.update(read_buf, 0, read_len);
                        fileOutputStream.write(dec);
                    }
                    byte[] dec = cipher.doFinal();
                    fileOutputStream.write(dec);
                }
            }
        }
    }
}