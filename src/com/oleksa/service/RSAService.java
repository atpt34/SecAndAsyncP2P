package com.oleksa.service;

import java.math.BigInteger;
import java.util.concurrent.ThreadLocalRandom;

public final class RSAService {

    public static byte[] encrypt(byte[] message, RSAPublicKey publicKey) {
        BigInteger msgInt = new BigInteger(message);
        BigInteger encrypted = msgInt.modPow(publicKey.E, publicKey.modulus);
        return encrypted.toByteArray();
    }

    public static byte[] decrypt(byte[] encrypted, RSAPrivateKey privateKey) {
        BigInteger encryptedInt = new BigInteger(encrypted);
        BigInteger decrypted = encryptedInt.modPow(privateKey.d, privateKey.modulus);
        return decrypted.toByteArray();
    }

    public static RSAPublicKey publicKeyOfModulus(byte[] modulus) {
        return new RSAPublicKey(new BigInteger(modulus));
    }

    public static RSAPublicKey publicKeyOfModulus(BigInteger modulus) {
        return new RSAPublicKey(modulus);
    }

    public static RSAPrivateKey generatePrivateKey() {
        BigInteger p;
        BigInteger q;
        do {
            p = BigInteger.probablePrime(RSAPublicKey.BITS, ThreadLocalRandom.current());
            q = BigInteger.probablePrime(RSAPublicKey.BITS, ThreadLocalRandom.current());
        } while (!areStrongKeys(p, q));
        return new RSAPrivateKey(p, q);
    }

    private static boolean areStrongKeys(BigInteger p, BigInteger q) {
        return BigInteger.TEN
                .compareTo(
                        p.subtract(BigInteger.ONE).gcd(q.subtract(BigInteger.ONE))) > 0
                &&
                p.subtract(q).abs().multiply(BigInteger.valueOf(100)).divide(p.min(q))
                .compareTo(BigInteger.TWO) > 0;
    }

    public static class RSAPublicKey {
        protected static final int BITS = 2048;
        protected static final BigInteger E = BigInteger.valueOf(0x10001);
        protected final BigInteger modulus;

        private RSAPublicKey(BigInteger modulus) {
            this.modulus = modulus;
        }

        public BigInteger getModulus() {
            return modulus;
        }
    }

    public static final class RSAPrivateKey extends RSAPublicKey {
        private final BigInteger p;
        private final BigInteger q;
        private final BigInteger phi;
        private final BigInteger d;

        private RSAPrivateKey(BigInteger p, BigInteger q){
            super(p.multiply(q));
            this.p = p;
            this.q = q;
            phi = p.subtract(BigInteger.ONE)
                    .multiply(
                            q.subtract(BigInteger.ONE));
            d = E.modInverse(phi);
        }

        public RSAPublicKey getPublicKey() {
            return this;
        }
    }
}
