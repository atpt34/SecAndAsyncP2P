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
    public void testReversibility() {
        String message = UUID.randomUUID().toString();

        byte[] bytes =
            RSAService.decrypt(
                RSAService.encrypt(message.getBytes(), privateKey),
                privateKey);

        assertEquals(message, new String(bytes), "operation should be reversible");
    }
}