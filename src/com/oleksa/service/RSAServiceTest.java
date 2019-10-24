package com.oleksa.service;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class RSAServiceTest {

    private static RSAService.RSAPrivateKey privateKey;

    @BeforeAll
    static void setup() {
        privateKey = RSAService.generatePrivateKey();
    }

    @Test
    public void testReversibilityBytes() {

        byte[] expected = new byte[]{ 127, -128, 0, -1};
        byte[] actual =
            RSAService.decrypt(
                RSAService.encrypt(expected, privateKey),
                privateKey);

        assertArrayEquals(expected, actual, "operation should be reversible");
    }

    @Test
    public void testReversibilityBytesNegative() {

        byte[] expected = new byte[]{ -128, 127, 0, -1};
        byte[] actual =
                RSAService.decrypt(
                        RSAService.encrypt(expected, privateKey),
                        privateKey);

        assertArrayEquals(expected, RSAService.returnComplement(actual, privateKey), "operation should be reversible");
    }

    @Test
    public void testReversibilityBytesOtherWay() {

        byte[] expected = new byte[]{ 127, 1, -128, -2, 0, -3, -1, 4};
        byte[] actual =
                RSAService.encrypt(
                        RSAService.decrypt(expected, privateKey),
                        privateKey);

        assertArrayEquals(expected, actual, "operation should be reversible");
    }

    @Test
    public void testReversibilityString() {
        String message = UUID.randomUUID().toString();

        byte[] bytes =
                RSAService.decrypt(
                        RSAService.encrypt(message.getBytes(), privateKey),
                        privateKey);

        assertEquals(message, new String(bytes), "operation should be reversible");
    }
}