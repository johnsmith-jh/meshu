package meshu.gateway.mint;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Component;

/**
 * Minimal Cashu mint HTTP client (NUT-01/02/03/06/07/09) over {@link HttpClient}.
 *
 * <p>The gateway daemon is the only component with internet access; it speaks
 * the ordinary Cashu JSON API to the configured mint (PoC: a remote mint; a
 * local Nutshell/CDK mint later). This class only translates HTTP/JSON — it has
 * no knowledge of Meshu framing, which lives in the op dispatcher.
 */
public class MintClient {

    private final String baseUrl; // e.g. https://mint.minibits.cash/Bitcoin
    private final HttpClient http;

    public MintClient(String baseUrl) {
        // Strip trailing slashes (NUT-00 normalization).
        this.baseUrl = baseUrl.replaceAll("/+$", "");
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    // ------------------------------------------------------------ NUT-02 keysets

    /** One keyset from GET /v1/keysets. */
    public record KeysetInfo(String id, String unit, boolean active, long inputFeePpk, Long finalExpiry) {
    }

    public List<KeysetInfo> getKeysets() throws MintException {
        String body = get("/v1/keysets");
        Json.Object root = Json.parseObject(body);
        List<KeysetInfo> out = new ArrayList<>();
        for (Json.Value v : root.getArray("keysets")) {
            Json.Object o = v.asObject();
            Long expiry = o.isNull("final_expiry") ? null : o.getLong("final_expiry");
            out.add(new KeysetInfo(
                    o.getString("id"),
                    o.getString("unit"),
                    o.getBool("active"),
                    o.optLong("input_fee_ppk", 0),
                    expiry));
        }
        return out;
    }

    // ------------------------------------------------------------ NUT-01/02 keys

    /**
     * Public keys for a keyset: amount → 33-byte compressed public key.
     * Returned as a map keyed by exponent (log2 of amount) for easy blob packing.
     */
    public Map<Integer, byte[]> getKeys(String keysetId) throws MintException {
        String body = get("/v1/keys/" + keysetId);
        Json.Object root = Json.parseObject(body);
        Json.Object keyset = root.getArray("keysets").get(0).asObject();
        Json.Object keys = keyset.getObject("keys");
        Map<Integer, byte[]> out = new LinkedHashMap<>();
        for (Map.Entry<String, Json.Value> e : keys.entrySet()) {
            int exponent = BigInteger.valueOf(Long.parseLong(e.getKey())).bitLength() - 1;
            out.put(exponent, hex(e.getValue().asString()));
        }
        return out;
    }

    // ------------------------------------------------------------ NUT-07 checkstate

    /** State of one proof. */
    public enum ProofState {UNSPENT, PENDING, SPENT}

    public List<ProofState> checkState(List<byte[]> ys) throws MintException {
        StringBuilder req = new StringBuilder("{\"Ys\":[");
        for (int i = 0; i < ys.size(); i++) {
            req.append(i > 0 ? "," : "").append('"').append(hexStr(ys.get(i))).append('"');
        }
        req.append("]}");
        String body = post("/v1/checkstate", req.toString());
        Json.Object root = Json.parseObject(body);
        List<ProofState> out = new ArrayList<>();
        for (Json.Value v : root.getArray("states")) {
            out.add(ProofState.valueOf(v.asObject().getString("state")));
        }
        return out;
    }

    // ------------------------------------------------------------ NUT-03 swap

    /** A Cashu Proof (input). */
    public record Proof(long amount, String keysetId, String secret, byte[] c) {
    }

    /** A Cashu BlindedMessage (output). */
    public record BlindedMessage(long amount, String keysetId, byte[] blinded) {
    }

    /** A Cashu BlindSignature (promise). */
    public record BlindSignature(long amount, String keysetId, byte[] c) {
    }

    public List<BlindSignature> swap(List<Proof> inputs, List<BlindedMessage> outputs) throws MintException {
        StringBuilder req = new StringBuilder("{\"inputs\":[");
        for (int i = 0; i < inputs.size(); i++) {
            Proof p = inputs.get(i);
            req.append(i > 0 ? "," : "")
                    .append("{\"amount\":").append(p.amount())
                    .append(",\"id\":\"").append(p.keysetId()).append('"')
                    .append(",\"secret\":\"").append(p.secret()).append('"')
                    .append(",\"C\":\"").append(hexStr(p.c())).append("\"}");
        }
        req.append("],\"outputs\":[");
        for (int i = 0; i < outputs.size(); i++) {
            BlindedMessage o = outputs.get(i);
            req.append(i > 0 ? "," : "")
                    .append("{\"amount\":").append(o.amount())
                    .append(",\"id\":\"").append(o.keysetId()).append('"')
                    .append(",\"B_\":\"").append(hexStr(o.blinded())).append("\"}");
        }
        req.append("]}");
        return parseSignatures(post("/v1/swap", req.toString()));
    }

    // ------------------------------------------------------------ NUT-09 restore

    /** Restore result: the outputs that were previously signed, with their signatures. */
    public record RestoreResult(List<BlindedMessage> outputs, List<BlindSignature> signatures) {
    }

    public RestoreResult restore(List<BlindedMessage> outputs) throws MintException {
        StringBuilder req = new StringBuilder("{\"outputs\":[");
        for (int i = 0; i < outputs.size(); i++) {
            BlindedMessage o = outputs.get(i);
            req.append(i > 0 ? "," : "")
                    .append("{\"amount\":").append(o.amount())
                    .append(",\"id\":\"").append(o.keysetId()).append('"')
                    .append(",\"B_\":\"").append(hexStr(o.blinded())).append("\"}");
        }
        req.append("]}");
        Json.Object root = Json.parseObject(post("/v1/restore", req.toString()));
        List<BlindedMessage> outs = new ArrayList<>();
        for (Json.Value v : root.getArray("outputs")) {
            Json.Object o = v.asObject();
            outs.add(new BlindedMessage(o.getLong("amount"), o.getString("id"), hex(o.getString("B_"))));
        }
        List<BlindSignature> sigs = new ArrayList<>();
        for (Json.Value v : root.getArray("signatures")) {
            Json.Object o = v.asObject();
            sigs.add(new BlindSignature(o.getLong("amount"), o.getString("id"), hex(o.getString("C_"))));
        }
        return new RestoreResult(outs, sigs);
    }

    // ------------------------------------------------------------ NUT-06 mint info

    /** Raw mint-info JSON (gateway projects a subset onto the wire, §8.12). */
    public String getMintInfo() throws MintException {
        return get("/v1/info");
    }

    // ------------------------------------------------------------ HTTP plumbing

    private String get(String path) throws MintException {
        return send(HttpRequest.newBuilder(URI.create(baseUrl + path)).GET());
    }

    private String post(String path, String json) throws MintException {
        return send(HttpRequest.newBuilder(URI.create(baseUrl + path))
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .header("Content-Type", "application/json"));
    }

    private String send(HttpRequest.Builder b) throws MintException {
        HttpResponse<String> resp;
        try {
            resp = http.send(b.timeout(Duration.ofSeconds(15)).build(),
                    HttpResponse.BodyHandlers.ofString());
        } catch (java.net.http.HttpTimeoutException e) {
            throw new MintException(MintException.Kind.TIMEOUT, null, "mint timeout");
        } catch (java.io.IOException e) {
            throw new MintException(MintException.Kind.TRANSPORT, null,
                    "mint unreachable: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new MintException(MintException.Kind.TRANSPORT, null, "interrupted", e);
        }
        if (resp.statusCode() / 100 != 2) {
            // Cashu error bodies carry {"code": <int>, "detail": <str>}
            // (error_codes.md). Forward the numeric code so the wallet gets
            // deterministic semantics (11001 spent ≠ indeterminate transport
            // failure); only genuinely non-Cashu bodies fall back to 0xF009.
            Long cashuCode = parseCashuCode(resp.body());
            if (cashuCode != null) {
                throw new MintException(MintException.Kind.CASHU, cashuCode,
                        "mint " + resp.statusCode() + " code " + cashuCode);
            }
            throw new MintException(MintException.Kind.HTTP, null,
                    "mint HTTP " + resp.statusCode() + ": " + truncate(resp.body()));
        }
        return resp.body();
    }

    /** Extract {@code code} from a Cashu JSON error body, if present. */
    private static Long parseCashuCode(String body) {
        if (body == null || body.isBlank()) {
            return null;
        }
        try {
            Json.Object o = Json.parseObject(body);
            if (!o.isNull("code")) {
                String raw = ((Json.Value.Num) o.get("code")).raw();
                return Long.parseLong(raw);
            }
        } catch (RuntimeException ignored) {
            // not JSON / not Cashu-shaped
        }
        return null;
    }

    private static String truncate(String s) {
        return s == null ? "" : s.substring(0, Math.min(s.length(), 300));
    }

    private static List<BlindSignature> parseSignatures(String body) {
        Json.Object root = Json.parseObject(body);
        List<BlindSignature> out = new ArrayList<>();
        for (Json.Value v : root.getArray("signatures")) {
            Json.Object o = v.asObject();
            out.add(new BlindSignature(o.getLong("amount"), o.getString("id"), hex(o.getString("C_"))));
        }
        return out;
    }

    // ------------------------------------------------------------ hex helpers

    public static byte[] hex(String s) {
        int n = s.length() / 2;
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    public static String hexStr(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(Character.forDigit((x >> 4) & 0xF, 16)).append(Character.forDigit(x & 0xF, 16));
        }
        return sb.toString();
    }

    /**
     * Mint call failure, classified per §10.2/§10.3:
     * <ul>
     *   <li>{@link Kind#CASHU} — the mint returned a Cashu error body; {@code cashuCode}
     *       is deterministic and MUST be forwarded to the wallet verbatim
     *       (11001 spent is NOT indeterminate).</li>
     *   <li>{@link Kind#TIMEOUT} — mint did not respond in time → MC_MINT_TIMEOUT (indeterminate).</li>
     *   <li>{@link Kind#TRANSPORT} — could not reach the mint → MC_MINT_UNREACHABLE (indeterminate).</li>
     *   <li>{@link Kind#HTTP} — non-Cashu HTTP error → MC_MINT_HTTP_ERROR.</li>
     * </ul>
     */
    public static final class MintException extends Exception {
        public enum Kind {CASHU, TIMEOUT, TRANSPORT, HTTP}

        private final Kind kind;
        private final Long cashuCode;

        public MintException(Kind kind, Long cashuCode, String message) {
            super(message);
            this.kind = kind;
            this.cashuCode = cashuCode;
        }

        public MintException(Kind kind, Long cashuCode, String message, Throwable cause) {
            super(message, cause);
            this.kind = kind;
            this.cashuCode = cashuCode;
        }

        public Kind kind() {
            return kind;
        }

        /** Numeric Cashu error code (error_codes.md), or null for non-Cashu failures. */
        public Long cashuCode() {
            return cashuCode;
        }
    }
}
