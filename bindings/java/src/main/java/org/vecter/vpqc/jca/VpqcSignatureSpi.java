package org.vecter.vpqc.jca;

import java.io.ByteArrayOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import org.vecter.vpqc.Vpqc;
import org.vecter.vpqc.VpqcException;

/**
 * {@code Signature} "VPQC-SIG". The algorithm (composite, ML-DSA, Ed25519) is determined by the
 * key. A context must be set with {@link VpqcSignatureParameterSpec} before signing or
 * verifying; the message is buffered because composite signatures sign the whole message.
 */
final class VpqcSignatureSpi extends SignatureSpi {
    private VpqcKeys.VpqcPrivateKey signingKey;
    private VpqcKeys.VpqcPublicKey verifyKey;
    private byte[] context;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    @Override
    protected void engineInitSign(PrivateKey key) throws InvalidKeyException {
        VpqcKeys.VpqcPrivateKey k = VpqcKeys.privateKey(key);
        if (!VpqcKeys.isSignature(k.algorithmId())) {
            throw new InvalidKeyException("not a signing key");
        }
        signingKey = k;
        verifyKey = null;
        buffer.reset();
    }

    @Override
    protected void engineInitVerify(PublicKey key) throws InvalidKeyException {
        VpqcKeys.VpqcPublicKey k = VpqcKeys.publicKey(key);
        if (!VpqcKeys.isSignature(k.algorithmId())) {
            throw new InvalidKeyException("not a verification key");
        }
        verifyKey = k;
        signingKey = null;
        buffer.reset();
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
        if (!(params instanceof VpqcSignatureParameterSpec spec)) {
            throw new InvalidAlgorithmParameterException("expected VpqcSignatureParameterSpec");
        }
        context = spec.getContext();
    }

    @Override
    protected void engineUpdate(byte b) {
        buffer.write(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) {
        buffer.write(b, off, len);
    }

    private byte[] requireContext() throws SignatureException {
        if (context == null) {
            throw new SignatureException(
                    "vpqc requires a signature context: call setParameter(new VpqcSignatureParameterSpec(\"my-app/purpose\"))");
        }
        return context;
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (signingKey == null) {
            throw new SignatureException("not initialized for signing");
        }
        byte[] msg = buffer.toByteArray();
        buffer.reset();
        try {
            return Vpqc.sign(signingKey.toVpqc(), msg, requireContext());
        } catch (VpqcException e) {
            throw new SignatureException(e.getMessage(), e);
        } finally {
            Arrays.fill(msg, (byte) 0);
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (verifyKey == null) {
            throw new SignatureException("not initialized for verification");
        }
        byte[] msg = buffer.toByteArray();
        buffer.reset();
        try {
            Vpqc.verify(verifyKey.toVpqc(), msg, requireContext(), sigBytes);
            return true;
        } catch (VpqcException.VerificationException e) {
            return false;
        } catch (VpqcException e) {
            throw new SignatureException(e.getMessage(), e);
        }
    }

    @Override
    @Deprecated
    protected void engineSetParameter(String param, Object value) {
        throw new UnsupportedOperationException("use setParameter(AlgorithmParameterSpec)");
    }

    @Override
    @Deprecated
    protected Object engineGetParameter(String param) {
        throw new UnsupportedOperationException();
    }
}
