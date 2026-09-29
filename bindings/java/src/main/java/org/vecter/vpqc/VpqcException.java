package org.vecter.vpqc;

/** Base class for failures reported by the native library. */
public class VpqcException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final int code;

    /**
     * Creates an exception.
     *
     * @param code native status code
     * @param message description
     */
    public VpqcException(int code, String message) {
        super(message);
        this.code = code;
    }

    /** @return the native status code (see {@code vpqc.h}) */
    public int code() {
        return code;
    }

    static VpqcException of(int code, String message) {
        return switch (code) {
            case 8 -> new DecryptionException(code, message);
            case 9 -> new VerificationException(code, message);
            case 1, 3, 4, 5, 6, 10 -> new InvalidInputException(code, message);
            case 11 -> new IoException(code, message);
            default -> new VpqcException(code, message);
        };
    }

    /** Decryption failed: wrong key, wrong context, or tampered data. */
    public static final class DecryptionException extends VpqcException {
        private static final long serialVersionUID = 1L;

        DecryptionException(int code, String message) {
            super(code, message);
        }
    }

    /** A signature is not valid for this key, message and context. */
    public static final class VerificationException extends VpqcException {
        private static final long serialVersionUID = 1L;

        VerificationException(int code, String message) {
            super(code, message);
        }
    }

    /** A key, envelope or argument is malformed or of the wrong kind. */
    public static final class InvalidInputException extends VpqcException {
        private static final long serialVersionUID = 1L;

        InvalidInputException(int code, String message) {
            super(code, message);
        }
    }

    /** An operating-system I/O error (file not found, permission denied, disk full, ...). */
    public static final class IoException extends VpqcException {
        private static final long serialVersionUID = 1L;

        IoException(int code, String message) {
            super(code, message);
        }
    }
}
