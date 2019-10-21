package com.oleksa.service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Base64;

public class EncryptionWithSignatureService {

    public static String encrypt(String message, RSAService.RSAPublicKey publicKey) {
        byte[] encrypted = RSAService.encrypt(message.getBytes(), publicKey);
        return toBase64String(encrypted);
    }

    public static String decrypt(String chipertext, RSAService.RSAPrivateKey privateKey) {
        byte[] decoded = fromBase64Bytes(chipertext);
        byte[] decrypted = RSAService.decrypt(decoded, privateKey);
        return new String(decrypted);
    }

    // enc & dec with signature

    static String toBase64String(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    static byte[] fromBase64Bytes(String base64) {
        return Base64.getDecoder().decode(base64);
    }

    private static MessageDigest instance;
    static {
        try {
            instance = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
    private static byte[] sha256(byte[] bytes) {
        return instance.digest(bytes);
    }

    private static long minuteTimestamp() {
        return LocalDateTime.now()
                .withNano(0)
                .withSecond(0)
                .toEpochSecond(ZoneOffset.UTC);
    }

    public static String publicKeyToString(RSAService.RSAPublicKey publicKey) {
        return toBase64String(publicKey.getModulus().toByteArray());
    }

    public static RSAService.RSAPublicKey publicKeyFromString(String encodedKey) {
        return RSAService.publicKeyOfModulus(fromBase64Bytes(encodedKey));
    }
}
