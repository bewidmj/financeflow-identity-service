package com.learning.financeflow.identity.security;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

public final class JwtKeyProvider {

    private static final int MINIMUM_RSA_BITS = 2048;
    private static final Pattern KEY_ID_PATTERN =
            Pattern.compile("[A-Za-z0-9._-]{1,128}");

    private final String activeKeyId;
    private final PrivateKey activePrivateKey;
    private final Map<String, RSAPublicKey> publicKeys;

    public JwtKeyProvider(
            ResourceLoader resourceLoader,
            String privateKeyLocation,
            String activeKeyId,
            String additionalPublicKeyLocations) {
        validateKeyId(activeKeyId);
        this.activeKeyId = activeKeyId;
        this.activePrivateKey = loadPrivateKey(resourceLoader, privateKeyLocation);

        Map<String, RSAPublicKey> configuredKeys = new LinkedHashMap<>();
        configuredKeys.put(activeKeyId, derivePublicKey(activePrivateKey));
        for (ConfiguredPublicKey configuredKey :
                parseAdditionalKeyLocations(additionalPublicKeyLocations)) {
            validateKeyId(configuredKey.keyId());
            if (configuredKeys.containsKey(configuredKey.keyId())) {
                throw new IllegalStateException("JWT key IDs must be unique");
            }
            configuredKeys.put(
                    configuredKey.keyId(),
                    loadPublicKey(resourceLoader, configuredKey.location()));
        }
        this.publicKeys = Map.copyOf(configuredKeys);
    }

    public String activeKeyId() {
        return activeKeyId;
    }

    public PrivateKey activePrivateKey() {
        return activePrivateKey;
    }

    public RSAPublicKey verificationKey(String keyId) {
        return publicKeys.get(keyId);
    }

    public List<Map<String, String>> jwkSet() {
        List<Map<String, String>> keys = new ArrayList<>();
        publicKeys.forEach((keyId, key) -> keys.add(Map.of(
                "kty", "RSA",
                "use", "sig",
                "alg", "RS256",
                "kid", keyId,
                "n", base64UrlUnsigned(key.getModulus()),
                "e", base64UrlUnsigned(key.getPublicExponent()))));
        return List.copyOf(keys);
    }

    private static PrivateKey loadPrivateKey(
            ResourceLoader resourceLoader, String location) {
        if (location == null || !location.startsWith("file:")) {
            throw new IllegalStateException(
                    "JWT private key must use an external file: PEM location");
        }
        byte[] der = readPem(resourceLoader, location, "PRIVATE KEY");
        try {
            PrivateKey key = KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(der));
            if (!(key instanceof RSAPrivateCrtKey rsaKey)
                    || rsaKey.getModulus().bitLength() < MINIMUM_RSA_BITS) {
                throw new IllegalStateException(
                        "JWT private key must be an RSA PKCS#8 key of at least 2048 bits");
            }
            return key;
        } catch (Exception ex) {
            if (ex instanceof IllegalStateException stateException) {
                throw stateException;
            }
            throw new IllegalStateException(
                    "JWT private key must be a valid RSA PKCS#8 PEM file", ex);
        }
    }

    private static RSAPublicKey derivePublicKey(PrivateKey privateKey) {
        RSAPrivateCrtKey rsaPrivateKey = (RSAPrivateCrtKey) privateKey;
        try {
            RSAPublicKey publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(
                    new RSAPublicKeySpec(
                            rsaPrivateKey.getModulus(),
                            rsaPrivateKey.getPublicExponent()));
            validateKeyPair(privateKey, publicKey);
            return publicKey;
        } catch (Exception ex) {
            if (ex instanceof IllegalStateException stateException) {
                throw stateException;
            }
            throw new IllegalStateException(
                    "Unable to derive the JWT public key from the RSA private key", ex);
        }
    }

    private static void validateKeyPair(PrivateKey privateKey, RSAPublicKey publicKey)
            throws Exception {
        byte[] challenge = "financeflow-rs256-key-validation"
                .getBytes(StandardCharsets.US_ASCII);
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(challenge);
        byte[] signedChallenge = signer.sign();

        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(challenge);
        if (!verifier.verify(signedChallenge)) {
            throw new IllegalStateException(
                    "Configured RSA private key does not match its public key");
        }
    }

    private static RSAPublicKey loadPublicKey(
            ResourceLoader resourceLoader, String location) {
        byte[] der = readPem(resourceLoader, location, "PUBLIC KEY");
        try {
            var key = KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(der));
            if (!(key instanceof RSAPublicKey rsaKey)
                    || rsaKey.getModulus().bitLength() < MINIMUM_RSA_BITS) {
                throw new IllegalStateException(
                        "Additional JWT public keys must be RSA keys of at least 2048 bits");
            }
            return rsaKey;
        } catch (Exception ex) {
            if (ex instanceof IllegalStateException stateException) {
                throw stateException;
            }
            throw new IllegalStateException(
                    "Additional JWT public keys must be valid RSA SubjectPublicKeyInfo PEM files",
                    ex);
        }
    }

    private static byte[] readPem(
            ResourceLoader resourceLoader, String location, String expectedType) {
        if (location == null || location.isBlank()) {
            throw new IllegalStateException("JWT key location is required");
        }
        Resource resource = resourceLoader.getResource(location);
        try (InputStream input = resource.getInputStream()) {
            String pem = new String(input.readAllBytes(), StandardCharsets.US_ASCII);
            String begin = "-----BEGIN " + expectedType + "-----";
            String end = "-----END " + expectedType + "-----";
            int beginIndex = pem.indexOf(begin);
            int endIndex = pem.indexOf(end);
            if (beginIndex < 0 || endIndex <= beginIndex
                    || pem.indexOf(begin, beginIndex + begin.length()) >= 0) {
                throw new IllegalStateException(
                        "Configured JWT key is not a valid " + expectedType + " PEM file");
            }
            String encoded = pem.substring(beginIndex + begin.length(), endIndex)
                    .replaceAll("\\s", "");
            try {
                return Base64.getDecoder().decode(encoded);
            } catch (IllegalArgumentException ex) {
                throw new IllegalStateException(
                        "Configured JWT key contains invalid PEM Base64 data", ex);
            }
        } catch (IOException ex) {
            throw new IllegalStateException(
                    "Unable to read configured JWT key file", ex);
        }
    }

    private static List<ConfiguredPublicKey> parseAdditionalKeyLocations(String value) {
        if (value == null || value.isBlank()) {
            return List.of();
        }
        List<ConfiguredPublicKey> configuredKeys = new ArrayList<>();
        for (String entry : value.split(",")) {
            int separator = entry.indexOf('=');
            if (separator < 1 || separator == entry.length() - 1) {
                throw new IllegalStateException(
                        "JWT_ADDITIONAL_PUBLIC_KEYS entries must use kid=PEM-location format");
            }
            configuredKeys.add(new ConfiguredPublicKey(
                    entry.substring(0, separator).trim(),
                    entry.substring(separator + 1).trim()));
        }
        return configuredKeys;
    }

    private static void validateKeyId(String keyId) {
        if (keyId == null || !KEY_ID_PATTERN.matcher(keyId).matches()) {
            throw new IllegalStateException(
                    "JWT key IDs must contain 1-128 letters, digits, dots, underscores, or hyphens");
        }
    }

    private static String base64UrlUnsigned(BigInteger value) {
        byte[] bytes = value.toByteArray();
        int offset = bytes.length > 1 && bytes[0] == 0 ? 1 : 0;
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(java.util.Arrays.copyOfRange(bytes, offset, bytes.length));
    }

    private record ConfiguredPublicKey(String keyId, String location) {
    }
}
