package org.example;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SimpleEcCurve {

    public X9ECParameters ecParameters;
    public ECDomainParameters ecDomainParameters;
    public BigInteger n;
    public ECPoint G;
    private int length4Hash;
//利用 Bouncy Castle 库获取指定椭圆曲线（如secp256r1）的参数，并基于这些参数进行后续计算
    public SimpleEcCurve(String curveName) {
        ecParameters = CustomNamedCurves.getByName(curveName);
        ecDomainParameters = new ECDomainParameters(ecParameters.getCurve(), ecParameters.getG(), ecParameters.getN());
        n = ecDomainParameters.getN();
        G = ecDomainParameters.getG();
        length4Hash = (n.bitLength() + 128) / 8 + 1;
    }
//将消息哈希映射到椭圆曲线上的点
    public ECPoint hash2Curve(byte[] message, MessageDigest hash) throws NoSuchAlgorithmException {
        byte[] messageHashBytes = hash.digest(message);
        BigInteger messageHash = new BigInteger(1, messageHashBytes).mod(n);
        while (true) {
            ECFieldElement x = ecDomainParameters.getCurve().fromBigInteger(messageHash);
            ECFieldElement y = x.square().add(ecDomainParameters.getCurve().getA()).multiply(x).add(ecDomainParameters.getCurve().getB()).sqrt();
            if (y == null) {
                messageHash = messageHash.add(BigInteger.ONE).mod(n);
                continue;
            }
            ECPoint ecPoint = ecDomainParameters.getCurve().createPoint(x.toBigInteger(), y.toBigInteger());
            ecPoint = ecPoint.multiply(ecDomainParameters.getCurve().getCofactor());
            if (ecPoint == null || !ecPoint.isValid()) {
                messageHash = messageHash.add(BigInteger.ONE).mod(n);
                continue;
            }
            return ecPoint;
        }
    }
//生成在椭圆曲线阶数范围内的随机大整数，为密钥生成等操作提供随机因子
    public BigInteger randomBigInteger(SecureRandom random) {
        BigInteger randomInt;
        do {
            randomInt = new BigInteger(n.bitLength(), random);
        } while (randomInt.compareTo(n) >= 0);
        return randomInt;
    }
    // public BigInteger hashToGroup (byte [] message, MessageDigest hash ){
    //使用 HMacKDF 将输入数据哈希到椭圆曲线的组中，用于生成特定的密钥或标识符
    public BigInteger hashToGroup2(byte[] input, byte[] clientSecret) {
        HMacKDF hkdf;
        if (clientSecret == null) {
            hkdf = new HMacKDF("HMACSHA512", input);
        } else {
            hkdf = new HMacKDF("HMACSHA512", input, clientSecret);
        }

        BigInteger p = n;
        int groupSize = p.bitLength();
        int bytesToGenerate = (groupSize + 7) / 8;
        int extraBits = bytesToGenerate * 8 - groupSize;
        BigInteger iterationCounter = BigInteger.ONE;

        while (true) {
            byte[] tBytes = hkdf.createKey(iterationCounter.toByteArray(), bytesToGenerate);
            BigInteger t = (new BigInteger(1, tBytes)).shiftRight(extraBits);
            if (t.compareTo(p) < 0 && t.compareTo(BigInteger.ZERO) > 0) {
                return t;
            }

            iterationCounter = iterationCounter.add(BigInteger.ONE);
        }
    }

}
