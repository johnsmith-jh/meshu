package meshu.core.l3;

import java.util.ArrayList;
import java.util.List;

/**
 * Packed blob formats (PROTOCOL.md §6.7) — binary packing for repetitive
 * cryptographic material, avoiding per-item CBOR framing.
 *
 * <ul>
 *   <li><b>Outputs blob</b> — {@code n × 34}: exponent (1) ‖ B_ (33 compressed secp256k1)</li>
 *   <li><b>Signatures blob</b> — {@code n × 33}: C_ (33)</li>
 *   <li><b>Proofs blob</b> — {@code n × 66}: exponent (1) ‖ secret (32) ‖ C (33)</li>
 *   <li><b>Y blob</b> — {@code n × 33}: Y (33) for CHECKSTATE</li>
 *   <li><b>Keys blob</b> — {@code 64 × 33}: entry i = public key for amount 2^i</li>
 * </ul>
 */
public final class PackedBlobs {

    private PackedBlobs() {
    }

    // ------------------------------------------------------------ outputs

    public record Output(int exponent, byte[] blindedMessage) {
        public Output {
            if (blindedMessage.length != 33) {
                throw new IllegalArgumentException("B_ must be 33 bytes, got " + blindedMessage.length);
            }
            if (exponent < 0 || exponent > 63) {
                throw new IllegalArgumentException("exponent out of range: " + exponent);
            }
        }
    }

    public static byte[] packOutputs(List<Output> outputs) {
        byte[] blob = new byte[outputs.size() * 34];
        for (int i = 0; i < outputs.size(); i++) {
            Output o = outputs.get(i);
            blob[i * 34] = (byte) o.exponent();
            System.arraycopy(o.blindedMessage(), 0, blob, i * 34 + 1, 33);
        }
        return blob;
    }

    public static List<Output> unpackOutputs(byte[] blob) {
        if (blob.length % 34 != 0) {
            throw new IllegalArgumentException("outputs blob length not a multiple of 34: " + blob.length);
        }
        List<Output> out = new ArrayList<>(blob.length / 34);
        for (int i = 0; i < blob.length; i += 34) {
            byte[] b = new byte[33];
            System.arraycopy(blob, i + 1, b, 0, 33);
            out.add(new Output(blob[i] & 0xFF, b));
        }
        return out;
    }

    // ------------------------------------------------------------ signatures

    public static byte[] packSignatures(List<byte[]> signatures) {
        byte[] blob = new byte[signatures.size() * 33];
        for (int i = 0; i < signatures.size(); i++) {
            byte[] c = signatures.get(i);
            if (c.length != 33) {
                throw new IllegalArgumentException("C_ must be 33 bytes, got " + c.length);
            }
            System.arraycopy(c, 0, blob, i * 33, 33);
        }
        return blob;
    }

    public static List<byte[]> unpackSignatures(byte[] blob) {
        if (blob.length % 33 != 0) {
            throw new IllegalArgumentException("signatures blob length not a multiple of 33: " + blob.length);
        }
        List<byte[]> out = new ArrayList<>(blob.length / 33);
        for (int i = 0; i < blob.length; i += 33) {
            byte[] c = new byte[33];
            System.arraycopy(blob, i, c, 0, 33);
            out.add(c);
        }
        return out;
    }

    // ------------------------------------------------------------ proofs

    public record Proof(int exponent, byte[] secret, byte[] c) {
        public Proof {
            if (secret.length != 32) {
                throw new IllegalArgumentException("secret must be 32 bytes, got " + secret.length);
            }
            if (c.length != 33) {
                throw new IllegalArgumentException("C must be 33 bytes, got " + c.length);
            }
        }
    }

    public static byte[] packProofs(List<Proof> proofs) {
        byte[] blob = new byte[proofs.size() * 66];
        for (int i = 0; i < proofs.size(); i++) {
            Proof p = proofs.get(i);
            blob[i * 66] = (byte) p.exponent();
            System.arraycopy(p.secret(), 0, blob, i * 66 + 1, 32);
            System.arraycopy(p.c(), 0, blob, i * 66 + 33, 33);
        }
        return blob;
    }

    public static List<Proof> unpackProofs(byte[] blob) {
        if (blob.length % 66 != 0) {
            throw new IllegalArgumentException("proofs blob length not a multiple of 66: " + blob.length);
        }
        List<Proof> out = new ArrayList<>(blob.length / 66);
        for (int i = 0; i < blob.length; i += 66) {
            byte[] secret = new byte[32];
            byte[] c = new byte[33];
            System.arraycopy(blob, i + 1, secret, 0, 32);
            System.arraycopy(blob, i + 33, c, 0, 33);
            out.add(new Proof(blob[i] & 0xFF, secret, c));
        }
        return out;
    }

    // ------------------------------------------------------------ Y blob (CHECKSTATE)

    public static byte[] packYs(List<byte[]> ys) {
        return packSignatures(ys); // same layout: n × 33
    }

    public static List<byte[]> unpackYs(byte[] blob) {
        return unpackSignatures(blob);
    }

    // ------------------------------------------------------------ keys blob

    public static byte[] packKeys(List<byte[]> keys) {
        if (keys.size() != 64) {
            throw new IllegalArgumentException("keys blob must hold exactly 64 keys, got " + keys.size());
        }
        return packSignatures(keys);
    }

    public static List<byte[]> unpackKeys(byte[] blob) {
        if (blob.length != 64 * 33) {
            throw new IllegalArgumentException("keys blob must be 64×33 = 2112 bytes, got " + blob.length);
        }
        return unpackSignatures(blob);
    }
}
