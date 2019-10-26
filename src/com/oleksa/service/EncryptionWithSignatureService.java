package com.oleksa.service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;

public class EncryptionWithSignatureService {

    public static String encrypt(String message, RSAService.RSAPublicKey publicKey) {
        return toBase64String(RSAService.encrypt(message.getBytes(), publicKey));
    }

    public static String encryptWithSignature(String message,
                                              RSAService.RSAPublicKey publicKey, RSAService.RSAPrivateKey privateKey,
                                              ExecutorService executorService) {
        byte[] messageBytes = message.getBytes();
        CompletableFuture<String> encryptedMessageB64 = CompletableFuture
                .supplyAsync(() -> concatArrays(messageBytes, longToBytes(nowTimestamp())), executorService)
                .thenApply(messageWithTimestamp -> RSAService.encrypt(messageWithTimestamp, publicKey))
                .thenApply(EncryptionWithSignatureService::toBase64String);
        byte[] digestBytes = sha256(concatArrays(messageBytes, longToBytes(secondTimestamp())));
        byte[] digestWithTimestamp = concatArrays(digestBytes, longToBytes(nowTimestamp()));
        String encryptedDigestB64 = toBase64String(RSAService.decrypt(digestWithTimestamp, privateKey));
        return new StringBuilder()
                .append(encryptedMessageB64.join())
                .append("$")
                .append(encryptedDigestB64)
                .toString();
    }

    public static String decrypt(String ciphertext, RSAService.RSAPrivateKey privateKey) {
        byte[] decrypted = RSAService.decrypt(fromBase64Bytes(ciphertext), privateKey);
        return new String(decrypted);
    }

    public static String decryptWithSignature(String message,
                                              RSAService.RSAPrivateKey privateKey, RSAService.RSAPublicKey publicKey,
                                              ExecutorService executorService) {
        String[] splited = message.split("\\$");
        String ciphertext = splited[0];
        String cipherhash = splited[1];
        CompletableFuture<byte[]> decryptedHashWithTimestamp = CompletableFuture
                .supplyAsync(() -> fromBase64Bytes(cipherhash), executorService)
                .thenApply(cipherhashBytes -> RSAService.encrypt(cipherhashBytes, publicKey));
        CompletableFuture<byte[]> decryptedHash = decryptedHashWithTimestamp
                .thenApply(hashWithTS -> Arrays.copyOf(hashWithTS, hashWithTS.length - Long.BYTES));
        CompletableFuture<byte[]> decryptedHashComplement = decryptedHashWithTimestamp
                .thenApplyAsync(hash -> RSAService.returnComplement(hash, publicKey), executorService)
                .thenApply(hashWithTS -> Arrays.copyOf(hashWithTS, hashWithTS.length - Long.BYTES));
        byte[] decryptedMessageWithTimestamp = RSAService.decrypt(fromBase64Bytes(ciphertext), privateKey);
        byte[] decryptedMessage = Arrays.copyOf(decryptedMessageWithTimestamp,
                decryptedMessageWithTimestamp.length - Long.BYTES);
        CompletableFuture<String> decryptedMessageString = CompletableFuture
                .supplyAsync(() -> new String(decryptedMessage), executorService);
        byte[] hashBytes = sha256(concatArrays(decryptedMessage, longToBytes(secondTimestamp())));
        if (!Arrays.equals(hashBytes, decryptedHash.join()) &&
            !Arrays.equals(hashBytes, decryptedHashComplement.join())) {
            throw new RuntimeException("Signature verification failed!");
        }
        return decryptedMessageString.join();
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

    private static long secondTimestamp() {
        return LocalDateTime.now()
                .withNano(0)
                .toEpochSecond(ZoneOffset.UTC);
    }

    private static long nowTimestamp() {
        return LocalDateTime.now()
                .toEpochSecond(ZoneOffset.UTC);
    }

    public static String publicKeyToString(RSAService.RSAPublicKey publicKey) {
        return toBase64String(publicKey.getModulus().toByteArray());
    }

    public static RSAService.RSAPublicKey publicKeyFromString(String encodedKey) {
        return RSAService.publicKeyOfModulus(fromBase64Bytes(encodedKey));
    }
}
