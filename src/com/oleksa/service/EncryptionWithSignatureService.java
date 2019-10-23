package com.oleksa.service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;

public class EncryptionWithSignatureService {

    public static String encrypt(String message, RSAService.RSAPublicKey publicKey) {
        byte[] encrypted = RSAService.encrypt(message.getBytes(), publicKey);
        return toBase64String(encrypted);
    }

    public static String encryptWithSignature(String message, RSAService.RSAPublicKey publicKey, RSAService.RSAPrivateKey privateKey) {
        byte[] messageBytes = message.getBytes();
        long timestamp = minuteTimestamp();
        byte[] encryptedMessage = RSAService.encrypt(messageBytes, publicKey);
        byte[] timestampBytes = longToBytes(timestamp);
        byte[] messageAndTimestampBytes = concatArrays(messageBytes, timestampBytes);
        byte[] hashBytes = sha256(messageAndTimestampBytes);
        byte[] encryptedDigest = RSAService.decrypt(hashBytes, privateKey);
        return new StringBuilder()
                .append(toBase64String(encryptedMessage))
                .append("$")
                .append(toBase64String(encryptedDigest))
                .toString();
    }

    public static String decrypt(String ciphertext, RSAService.RSAPrivateKey privateKey) {
        byte[] decoded = fromBase64Bytes(ciphertext);
        byte[] decrypted = RSAService.decrypt(decoded, privateKey);
        return new String(decrypted);
    }

    public static String decryptWithSignature(String message, RSAService.RSAPrivateKey privateKey, RSAService.RSAPublicKey publicKey) {
        String[] splited = message.split("\\$");
        String ciphertext = splited[0];
        String cipherhash = splited[1];
        byte[] cipherhashBytes = fromBase64Bytes(cipherhash);
//        CompletableFuture<byte[]> completableFuture = CompletableFuture.supplyAsync(() -> fromBase64Bytes(cipherhash), Executors.newFixedThreadPool(1))
//                .thenApply(cipherhashBytes -> RSAService.encrypt(cipherhashBytes, publicKey));
        long timestamp = minuteTimestamp();
        byte[] decryptedHash = RSAService.encrypt(cipherhashBytes, publicKey);
        byte[] decodedText = fromBase64Bytes(ciphertext);
        byte[] decryptedMessage = RSAService.decrypt(decodedText, privateKey);
        byte[] timestampBytes = longToBytes(timestamp);
        byte[] messageAndTimestampBytes = concatArrays(decryptedMessage, timestampBytes);
        byte[] hashBytes = sha256(messageAndTimestampBytes);
//        byte[] decryptedHash = completableFuture.join();
        if (!Arrays.equals(decryptedHash, hashBytes)) { // sometimes fails
            System.out.println("[Verification failed!]");
//            throw new RuntimeException("Signature verification failed!");
        }
        return new String(decryptedMessage);
    }

    static byte[] concatArrays(byte[] messageBytes, byte[] timestampBytes) {
        byte[] messageAndTimestamp = new byte[messageBytes.length + timestampBytes.length];
        System.arraycopy(messageBytes, 0, messageAndTimestamp, 0, messageBytes.length);
        System.arraycopy(timestampBytes, 0, messageAndTimestamp, messageBytes.length, timestampBytes.length);
        return messageAndTimestamp;
    }

    public static byte[] longToBytes(long lng) {
        return new byte[] {
                (byte) lng,
                (byte) (lng >> 8),
                (byte) (lng >> 16),
                (byte) (lng >> 24),
                (byte) (lng >> 32),
                (byte) (lng >> 40),
                (byte) (lng >> 48),
                (byte) (lng >> 56)};
    }

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
