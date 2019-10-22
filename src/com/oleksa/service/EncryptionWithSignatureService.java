package com.oleksa.service;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;

public class EncryptionWithSignatureService {

    public static String encrypt(String message, RSAService.RSAPublicKey publicKey) {
        byte[] encrypted = RSAService.encrypt(message.getBytes(), publicKey);
        return toBase64String(encrypted);
    }

    public static String encryptWithSignature(String message, RSAService.RSAPrivateKey privateKey, RSAService.RSAPublicKey publicKey) {
        byte[] messageBytes = message.getBytes();
        long timestamp = minuteTimestamp();
        byte[] encryptedMessage = RSAService.encrypt(messageBytes, publicKey);
        byte[] timestampBytes = longToBytes(timestamp);
        byte[] messageAndTimestampBytes = concatArrays(messageBytes, timestampBytes);
        byte[] hashBytes = sha256(messageAndTimestampBytes);
        byte[] encryptedDigest = RSAService.decrypt(hashBytes, privateKey);
        return toBase64String(encryptedMessage) + "$" + toBase64String(encryptedDigest);
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
        long timestamp = minuteTimestamp();
        byte[] decryptedHash = RSAService.encrypt(cipherhashBytes, publicKey);
        byte[] decryptedMessage = RSAService.decrypt(fromBase64Bytes(ciphertext), privateKey);
        byte[] timestampBytes = longToBytes(timestamp);
        byte[] messageAndTimestampBytes = concatArrays(decryptedMessage, timestampBytes);
        byte[] hashBytes = sha256(messageAndTimestampBytes);
        if (!Arrays.equals(decryptedHash, hashBytes)) {
            throw new RuntimeException("Signature verification failed!");
        }
        return new String(decryptedMessage);
    }

    static byte[] concatArrays(byte[] messageBytes, byte[] timestampBytes) {
        byte[] messageAndTimestamp = new byte[messageBytes.length + timestampBytes.length];
        System.arraycopy(messageBytes, 0, messageAndTimestamp, 0, messageBytes.length);
        System.arraycopy(timestampBytes, 0, messageAndTimestamp, messageBytes.length, timestampBytes.length);
        return messageAndTimestamp;
    }

    public static byte[] longToBytes(long x) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(x);
        return buffer.array();
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
