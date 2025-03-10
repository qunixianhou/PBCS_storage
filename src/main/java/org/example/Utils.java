package org.example;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
/**
 * Author: Ya-Nan Li,
 */
//利用 Bouncy Castle 库获取指定椭圆曲线（如secp256r1）的参数，并基于这些参数进行后续计算
public class Utils {
    private Utils() {throw new AssertionError();
    }

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    /**
     * Convert Byte Array into Hex String
     *
     * @param bytes Byte Array
     * @return Hex String
     */
//将字节数组转换为十六进制字符串，方便数据展示和存储
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

//基于 PBKDF2WithHmacSHA256 算法实现密钥派生，根据输入的密钥、密码短语、盐、输出长度和哈希重复次数生成派生密钥
    public static byte[] KDF(byte[] key, String passphrase, byte[] salt, int outputLength,
                             int kdfHashRepetitions) {
        try {
            byte[] keyAndSalt = new byte[key.length + salt.length];
            System.arraycopy(salt, 0, keyAndSalt, 0, salt.length);
            System.arraycopy(key, 0, keyAndSalt, salt.length, key.length);

            KeySpec spec = new PBEKeySpec(passphrase.toCharArray(), keyAndSalt, kdfHashRepetitions,
                    outputLength);
            SecretKeyFactory factory;
            factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return factory.generateSecret(spec).getEncoded();

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
//安全地清除密码和密钥相关的数组内容，防止敏感信息泄露
    public static void destroyPassword(char[] password) {
        if (password != null)
            Arrays.fill(password, ' ');
    }

    public static void destroyPasskey(byte[] passkey) {
        if (passkey != null)
            Arrays.fill(passkey, (byte) 0);
    }

}
