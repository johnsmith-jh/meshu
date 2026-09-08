package meshu.gateway.http;

import meshu.gateway.session.SessionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * HTTPS transport binding (POC-WALLET.md §9).
 *
 * <p>When the wallet has ordinary internet access it talks to the <b>same
 * gateway daemon</b> speaking the <b>same protocol</b> — only the transport
 * differs. L3 messages and L2 encryption are unchanged; L1 segmentation and the
 * airtime governor are bypassed (HTTP is reliable and ordered), and only
 * {@code msg_id} is retained for its two security roles: idempotency key (§11)
 * and AEAD nonce input (§4.5).
 *
 * <p>Body form (§9.1): {@code msg_id (2 bytes BE) ‖ sealed L2 message}, and the
 * response has the same form reusing the request's {@code msg_id}. No L1 header,
 * no flags, no dst/src prefix — the HTTP round trip replaces routing and
 * reliability.
 *
 * <p><b>TLS is a hard deployment requirement</b> (§9.3): the wallet is a PWA
 * served over HTTPS and browsers block plain-HTTP/self-signed fetch. The daemon
 * must sit behind a CA-signed cert on a real domain (Caddy/nginx/Let's Encrypt),
 * with CORS enabled for the wallet's origin. There is no insecure-HTTP fallback.
 */
@RestController
@CrossOrigin // §9.3: CORS for the wallet's origin. Tighten to the wallet origin in deployment.
public class MeshuHttpController {

    private static final Logger log = LoggerFactory.getLogger(MeshuHttpController.class);

    /** The single endpoint path (§9.1). */
    public static final String PATH = "/meshu";

    private static final MediaType OCTET_STREAM = MediaType.APPLICATION_OCTET_STREAM;

    private final SessionService session;

    public MeshuHttpController(SessionService session) {
        this.session = session;
    }

    /**
     * Handle one sealed Meshu message over HTTPS.
     *
     * @param body {@code msg_id (2B BE) ‖ sealed L2 message}
     * @return {@code msg_id (2B BE) ‖ sealed L2 response} (same msg_id)
     */
    @PostMapping(path = PATH, consumes = "application/octet-stream", produces = "application/octet-stream")
    public ResponseEntity<byte[]> handle(@RequestBody byte[] body) {
        if (body.length < 3) { // 2-byte msg_id + at least 1 byte of L2
            return badRequest("body too short: need msg_id(2) + L2 message");
        }
        int msgId = ((body[0] & 0xFF) << 8) | (body[1] & 0xFF);
        byte[] l2Body = java.util.Arrays.copyOfRange(body, 2, body.length);

        byte[] l2Response;
        try {
            // src-hash hint is meaningless over HTTPS (§2.3 is a mesh concept);
            // pass -1 so the full pinned-key scan runs (§2.3 collision rule).
            l2Response = session.handleMessage(msgId, l2Body, -1);
        } catch (SessionService.DecryptFailedException e) {
            // §3.8/§4.6: unverifiable message → the wallet must re-bootstrap.
            // Over HTTPS there is no NACK frame, so 401 signals DECRYPT_FAILED.
            log.warn("decrypt failed for msg_id {}: {}", msgId, e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .contentType(OCTET_STREAM)
                    .body(msgIdBytes(msgId));
        } catch (SessionService.SessionException e) {
            log.warn("session error for msg_id {}: {}", msgId, e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .contentType(OCTET_STREAM)
                    .body(msgIdBytes(msgId));
        }

        // Response: msg_id ‖ sealed L2 response (§9.1).
        byte[] out = new byte[2 + l2Response.length];
        out[0] = (byte) (msgId >> 8);
        out[1] = (byte) msgId;
        System.arraycopy(l2Response, 0, out, 2, l2Response.length);
        return ResponseEntity.ok().contentType(OCTET_STREAM).body(out);
    }

    private static ResponseEntity<byte[]> badRequest(String why) {
        log.warn("rejected HTTPS request: {}", why);
        return ResponseEntity.badRequest().contentType(OCTET_STREAM).body(new byte[0]);
    }

    private static byte[] msgIdBytes(int msgId) {
        return new byte[]{(byte) (msgId >> 8), (byte) msgId};
    }
}
