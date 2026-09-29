package org.vecter.vpqc.jca;

import java.nio.charset.StandardCharsets;
import java.security.spec.AlgorithmParameterSpec;

/**
 * The domain-separation context of a signature (at most 255 bytes). vpqc requires every
 * signature to name its purpose, for example {@code "my-app/release-v1"}, so a signature made
 * for one purpose never verifies for another. Pass it with {@code Signature.setParameter}.
 */
public final class VpqcSignatureParameterSpec implements AlgorithmParameterSpec {
    private final byte[] context;

    /**
     * @param context context bytes (at most 255)
     */
    public VpqcSignatureParameterSpec(byte[] context) {
        if (context.length > 255) {
            throw new IllegalArgumentException("signature context longer than 255 bytes");
        }
        this.context = context.clone();
    }

    /**
     * @param context context as UTF-8 text
     */
    public VpqcSignatureParameterSpec(String context) {
        this(context.getBytes(StandardCharsets.UTF_8));
    }

    /** @return a copy of the context bytes */
    public byte[] getContext() {
        return context.clone();
    }
}
