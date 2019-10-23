package com.oleksa.service;

import java.math.BigInteger;
import java.util.concurrent.ThreadLocalRandom;

public final class RSAService {

    public static byte[] encrypt(byte[] message, RSAPublicKey publicKey) {
        BigInteger msgInt = new BigInteger(message);
        BigInteger encrypted = msgInt.modPow(publicKey.getPublicExponent(), publicKey.getModulus());
        return encrypted.toByteArray();
    }

    public static byte[] decrypt(byte[] encrypted, RSAPrivateKey privateKey) {
        BigInteger encryptedInt = new BigInteger(encrypted);
        BigInteger decrypted = encryptedInt.modPow(privateKey.getPrivateExponent(), privateKey.getModulus());
        return decrypted.toByteArray();
    }

    static RSAPublicKey publicKeyOfModulus(byte[] modulus) {
        return new RSAPublicKey(new BigInteger(modulus));
    }

    public static RSAPrivateKey generatePrivateKey() {
        BigInteger p;
        BigInteger q;
        do {
            p = BigInteger.probablePrime(RSAPublicKey.BITS, ThreadLocalRandom.current());
            q = BigInteger.probablePrime(RSAPublicKey.BITS, ThreadLocalRandom.current());
        } while (!areStrongKeys(p, q));
        return RSAPrivateKey.of(p, q);
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
        static final int BITS = 2048;
        static final BigInteger E = BigInteger.valueOf(0x10001);
        final BigInteger modulus;

        private RSAPublicKey(BigInteger modulus) {
            this.modulus = modulus;
        }

        BigInteger getPublicExponent() {
            return E;
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

        BigInteger getPrivateExponent() {
            return d;
        }

        static RSAPrivateKey of(BigInteger p, BigInteger q) {
            return new RSAPrivateKey(p, q);
        }
    }
}
