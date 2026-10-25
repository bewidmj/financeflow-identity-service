package com.learning.financeflow.identity;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public final class TestRsaKey {

    public static final KeyPair PAIR = generateKeyPair();
    private static final String PRIVATE_KEY_LOCATION = writePrivateKey(PAIR);

    private TestRsaKey() {
    }

    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("RSA is not available for tests", ex);
        }
    }

    public static String privateKeyLocation() {
        return PRIVATE_KEY_LOCATION;
    }

    public static String writePrivateKey(KeyPair pair) {
        return writePem("PRIVATE KEY", pair.getPrivate().getEncoded());
    }

    public static String writePublicKey(KeyPair pair) {
        return writePem("PUBLIC KEY", pair.getPublic().getEncoded());
    }

    private static String writePem(String label, byte[] der) {
        String encoded = Base64.getMimeEncoder(64, new byte[]{'\n'})
                .encodeToString(der);
        String pem = "-----BEGIN " + label + "-----\n"
                + encoded + "\n-----END " + label + "-----\n";
        try {
            Path file = Files.createTempFile("financeflow-test-jwt-", ".pem");
            file.toFile().deleteOnExit();
            Files.writeString(file, pem);
            return file.toUri().toString();
        } catch (IOException ex) {
            throw new IllegalStateException("Unable to prepare test RSA key", ex);
        }
    }
}
