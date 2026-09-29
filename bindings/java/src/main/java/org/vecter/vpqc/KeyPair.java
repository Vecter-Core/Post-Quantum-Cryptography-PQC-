package org.vecter.vpqc;

/**
 * A freshly generated key pair.
 *
 * @param publicKey the public key
 * @param secretKey the secret key
 */
public record KeyPair(PublicKey publicKey, SecretKey secretKey) {}
