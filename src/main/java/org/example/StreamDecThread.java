package org.example;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
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
    private final List<InputStream> list;
    private final String sourceInterPath;
    private final String desPath;
    private final byte[] msk;
    private final int partNum;

    public StreamDecThread(List<InputStream> decList, String sourceInterPath, String desPath, byte[] msk, int partNum) {
        this.list = decList;
        this.sourceInterPath = sourceInterPath;
        this.desPath = desPath;
        this.msk = msk;
        this.partNum = partNum;
    }

    public void run() {
        try {
            decryptStreamCTRCombine(sourceInterPath, desPath, msk, partNum);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void decryptStreamCTRCombine(String sourceInterPath, String desPath, byte[] msk, int partNum)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException, IOException {
        int index = 0;
        Cipher keyCipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKey mskKey = new SecretKeySpec(msk, Constants.KEY_ENCRYPTION_BASE_ALGORITHM);
        Cipher cipher = Cipher.getInstance(Constants.KEY_ENCRYPTION_CTR_ALGORITHM);

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
                    // 读取加密的数据密钥
                    int keyIvLen = input.read();
                    byte[] keyIv = new byte[keyIvLen];
                    input.read(keyIv);
                    int encKeyLen = input.read();
                    byte[] encryptedDataKey = new byte[encKeyLen];
                    input.read(encryptedDataKey);

                    // 解密数据密钥
                    keyCipher.init(Cipher.DECRYPT_MODE, mskKey, new GCMParameterSpec(Constants.GCM_TAG_LENGTH, keyIv));
                    byte[] dataKey = keyCipher.doFinal(encryptedDataKey);

                    // 解密文件数据
                    byte[] iv = new byte[Constants.KEY_ENCRYPTION_CTR_IV_LENGTH];
                    input.read(iv);
                    SecretKey dataKeySpec = new SecretKeySpec(dataKey, Constants.KEY_ENCRYPTION_BASE_ALGORITHM);
                    cipher.init(Cipher.DECRYPT_MODE, dataKeySpec, new IvParameterSpec(iv));

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