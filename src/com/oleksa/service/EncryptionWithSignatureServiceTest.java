package com.oleksa.service;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class EncryptionWithSignatureServiceTest {

    private static RSAService.RSAPrivateKey privateKey;
    private static RSAService.RSAPrivateKey privateKeyOther;

    @BeforeAll
    static void setup() {
        privateKey = RSAService.RSAPrivateKey.of(
                new BigInteger("79171700876741016327090752713106419095708740098543553969737498738474748533037"),
                new BigInteger("94549426310136672161719930911355403099154744465568469663412692261944878909481"));
        privateKeyOther = RSAService.RSAPrivateKey.of(
                new BigInteger("92488746158379567793074615200166169650424117327281618617847207901671105237533"),
                new BigInteger("89269254281373955335738100754166537020904187192316806027680265240100320424213")
        );
    }
    @Test
    public void testReversibility() {
        String message = UUID.randomUUID().toString();

        String decryptedMessage =
                EncryptionWithSignatureService.decrypt(
                        EncryptionWithSignatureService.encrypt(message, privateKey),
                        privateKey);

        assertEquals(message, decryptedMessage, "operation should be reversible");
    }

//    @Test
    public void testReversibilityOtherWay() {

        String message = UUID.randomUUID().toString();
        String messageB64 = EncryptionWithSignatureService.toBase64String(message.getBytes());
        String decrypt = EncryptionWithSignatureService.decrypt(messageB64, privateKey);
        String encrypt = EncryptionWithSignatureService.encrypt(decrypt, privateKey);
        byte[] bytes = EncryptionWithSignatureService.fromBase64Bytes(encrypt);
        String messageRev = new String(bytes);

        assertEquals(message, messageRev, "operation should be reversible");
        assertEquals(messageB64, encrypt, "operation should be reversible");
    }

    @Test
    public void testReversibilityWithSignature() {
        String message = UUID.randomUUID().toString();
        String encryptedWithSignature =
                EncryptionWithSignatureService.encryptWithSignature(message, privateKeyOther,  privateKey);
        String decryptedMessage =
                EncryptionWithSignatureService.decryptWithSignature(encryptedWithSignature, privateKeyOther, privateKey);

        assertEquals(message, decryptedMessage, "operation should be reversible");
    }

    @Test
    public void testReversibilityWithSignatureOtherWay() {
        String message = UUID.randomUUID().toString();
        String encryptedWithSignature =
                EncryptionWithSignatureService.encryptWithSignature(message, privateKey, privateKeyOther);
        String decryptedMessage =
                EncryptionWithSignatureService.decryptWithSignature(encryptedWithSignature, privateKey, privateKeyOther);

        assertEquals(message, decryptedMessage, "operation should be reversible");
    }

    @Test
    void testConcatArrays() {
        byte[] a = new byte[]{1, 2, 3, 4};
        byte[] b = new byte[]{5, 6};
        assertArrayEquals(new byte[]{1, 2, 3, 4, 5, 6},
                EncryptionWithSignatureService.concatArrays(a, b));
    }

    @Test
    void testDecode() {
        String base64 = "AKDB54gZPVJ1x9dZVWTuhVCJZaGd2r80IK3pS2SGZvZX27SB62aFcVFTDRAmvzpS3Yp7F9eAoU9BjroEpGNDGA6ErJDz4s4h8zpKiG2e301kxvu+ezp+Kf5kLE2XP3z9gnqzfxp982zoNuB5K9oNcw9UbjSbla/wajTowYjEElne5Q+lxG8olY56jKGljmtknf5RVM/QEAbcVGr3DGrj2AiTo6EglI5p+tRNtRdolEnoUz8wrTGKwA91mzQwQAO/S1zjbTK9ugmdxMfiGUY+KAzX0Rt7UouPyy8OwIBikmbDM/3cNQAo2elmrKSJ99WREvmTru/86QimpdHbrMVJx0c=";
        byte[] bytes = EncryptionWithSignatureService.fromBase64Bytes(base64);
        assertEquals(new BigInteger("20293746628018586110097212709025862027721386466896906864199372484995957220185345395898600525874164813297309509608851904844183672594004788310019978298128228617951146082554631093675228281507509493585270702637086756224651485852233302592335685886791449604519680405369637433964915759532953484666885394991002358495610989657882938964431281490094268186230437232086667057873998830993319362667931068335598403255296952397087484766206275726774572010110289642237032667655020110596609613934932147280739341240970060903322025630245782078046655851995905915602712039397808346452871879826624527779347532880657660935586067080762096207687"),
                new BigInteger(bytes));
    }

    @Test
    void testEncode() {
        String value = "18304439445945203662749725423096881637858087828153754063404547820370257355741999008200113264669244830126038718304404465551515592888030238327294298493158745484627262820046632462215644230832546896484714937748038217348425445643736002863391439748772093517498674051356825034294226166497975401706985640880766056678782479084245227659586881599743392209005363973384306900220699425735476955911767422747156929030332913775973941961838901109254401789595607186393472935174206329462452625156367530378053327574455127900805483574351538761639757390965131968978838593953677714441192560870825412262176528182200754177538901140288088228073";
        BigInteger bigIntegerValue = new BigInteger(value);
        String encoded = EncryptionWithSignatureService.toBase64String(bigIntegerValue.toByteArray());
        assertEquals("AJD/xGpitypuPiQsM+f+ZAlS6sZOjwqBuAFw/lBLf7L9W1bQIsZeqq2/A3Gxt0E95rvFWcKQwJVnVRejBf/RbEYfc6ZDqlzzrYBWHi3enGJ0QOWEMIpVFePJprqdAWTVpAg0UTYnrxpC+KNeXRSDFVjXLumjda1tFvc+6G8l2Vr2VjM/Dpe2LTtwXS99ddEi5MHl6ox3N6Lo9L1fED46GC+DTBdy3j+mJFqW9YEpAa0vc41fzFqMsrN+gZ3ggccB/LERGgw4CKs3qDbENrdAuhQN+SG30l1OrXD5d0BA7hSdJzXJmPBt9HH1rUPGUBR+2UU3gDxq1G4odnW4UPMSwOk=",
                encoded);
    }

    @Test
    void testBase64Reversibility() {
        String expectedString = "abcdefghijk=";
        byte[] expectedBytes = new byte[]{ 1, -1, 0, -128, 6, 127, -8};

        String actualString = EncryptionWithSignatureService.toBase64String(
                EncryptionWithSignatureService.fromBase64Bytes(expectedString));
        byte[] actualBytes = EncryptionWithSignatureService.fromBase64Bytes(
                EncryptionWithSignatureService.toBase64String(expectedBytes));

        assertEquals(expectedString, actualString, "String is not properly encoded/decoded");
        assertArrayEquals(expectedBytes, actualBytes, "byte[] is not properly encoded/decoded");

    }

}