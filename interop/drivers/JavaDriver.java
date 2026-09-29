import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.vecter.vpqc.KeyPair;
import org.vecter.vpqc.Profile;
import org.vecter.vpqc.PublicKey;
import org.vecter.vpqc.SecretKey;
import org.vecter.vpqc.Vpqc;
import org.vecter.vpqc.VpqcException;

/** Java driver for the interoperability suite. See interop/run.sh. */
public final class JavaDriver {
    private static byte[] read(String p) throws Exception {
        return Files.readAllBytes(Path.of(p));
    }

    private static String text(String p) throws Exception {
        return Files.readString(Path.of(p));
    }

    private static void write(String p, byte[] b) throws Exception {
        Files.write(Path.of(p), b);
    }

    public static void main(String[] args) throws Exception {
        String cmd = args[0];
        try {
            switch (cmd) {
                case "keygen" -> { // keygen encrypt|sign PROFILE_NAME OUT_PREFIX
                    Profile p = switch (args[2]) {
                        case "standard" -> Profile.STANDARD;
                        case "fast-auth" -> Profile.FAST_AUTH;
                        case "cnsa2" -> Profile.CNSA2;
                        case "high" -> Profile.HIGH;
                        default -> throw new IllegalArgumentException("profile " + args[2]);
                    };
                    KeyPair kp = args[1].equals("encrypt")
                            ? Vpqc.generateEncryptionKeypair(p)
                            : Vpqc.generateSigningKeypair(p);
                    write(args[3] + ".pub", kp.publicKey().toText().getBytes(StandardCharsets.UTF_8));
                    write(args[3] + ".sec", kp.secretKey().toText().getBytes(StandardCharsets.UTF_8));
                }
                case "seal" -> write(args[4], Vpqc.seal(PublicKey.fromText(text(args[1])), read(args[3]),
                        args[2].getBytes(StandardCharsets.UTF_8)));
                case "open" -> write(args[4], Vpqc.open(SecretKey.fromText(text(args[1])), read(args[3]),
                        args[2].getBytes(StandardCharsets.UTF_8)));
                case "sign" -> write(args[4], Vpqc.sign(SecretKey.fromText(text(args[1])), read(args[3]),
                        args[2].getBytes(StandardCharsets.UTF_8)));
                case "verify" -> Vpqc.verify(PublicKey.fromText(text(args[1])), read(args[4]),
                        args[2].getBytes(StandardCharsets.UTF_8), read(args[3]));
                case "encrypt-file" -> Vpqc.encryptFile(PublicKey.fromText(text(args[1])), Path.of(args[3]),
                        Path.of(args[4]), args[2].getBytes(StandardCharsets.UTF_8));
                case "decrypt-file" -> Vpqc.decryptFile(SecretKey.fromText(text(args[1])), Path.of(args[3]),
                        Path.of(args[4]), args[2].getBytes(StandardCharsets.UTF_8));
                default -> throw new IllegalArgumentException("unknown command " + cmd);
            }
        } catch (VpqcException | IllegalArgumentException e) {
            System.err.println("java-driver: " + e.getMessage());
            System.exit(1);
        }
    }
}
