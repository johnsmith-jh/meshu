package meshu.gateway.http;

import meshu.core.l2.KeyAgreement;
import meshu.core.l2.L2;
import meshu.core.l3.Envelope;
import meshu.core.l3.Op;
import meshu.core.l3.Ops;
import meshu.core.l3.PackedBlobs;
import meshu.gateway.mint.MintClient;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Full-stack HTTPS transport test: a simulated wallet seals messages with its
 * own X25519 key and POSTs them to {@code /meshu}; the gateway opens,
 * dispatches (to a stubbed mint), seals, and returns. Exercises the whole
 * pipeline over real HTTP semantics.
 */
@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:sqlite:file:testdb?mode=memory&cache=shared",
        "meshu.mint.url=https://mint.test/Bitcoin"
})
class MeshuHttpControllerTest {

    /** Stub the mint so the test needs no network. */
    @TestConfiguration
    static class StubMintConfig {
        @Bean
        @Primary
        MintClient stubMint() {
            return new StubMint();
        }
    }

    static class StubMint extends MintClient {
        StubMint() {
            super("https://mint.test/Bitcoin");
        }

        @Override
        public List<KeysetInfo> getKeysets() {
            List<KeysetInfo> ks = new ArrayList<>();
            ks.add(new KeysetInfo(
                    "01fc0ec0e59cd6fa01b7a88f8cd77fce81fd1e64bca67d752e984992b7a3c3a821",
                    "sat", true, 0, null));
            return ks;
        }

        @Override
        public Map<Integer, byte[]> getKeys(String keysetId) {
            Map<Integer, byte[]> keys = new LinkedHashMap<>();
            for (int e = 0; e < 17; e++) {
                byte[] k = new byte[33];
                k[0] = 0x02;
                k[32] = (byte) e;
                keys.put(e, k);
            }
            return keys;
        }

        @Override
        public List<ProofState> checkState(List<byte[]> ys) {
            List<ProofState> out = new ArrayList<>();
            for (int i = 0; i < ys.size(); i++) {
                out.add(ProofState.UNSPENT);
            }
            return out;
        }
    }

    @Autowired
    private WebApplicationContext wac;

    @Autowired
    private meshu.gateway.session.PairingService pairing;

    private MockMvc mvc() {
        return MockMvcBuilders.webAppContextSetup(wac).build();
    }

    private static byte[] rawPub(KeyPair kp) {
        byte[] enc = kp.getPublic().getEncoded();
        return Arrays.copyOfRange(enc, enc.length - 32, enc.length);
    }

    private static byte[] body(int msgId, byte[] l2) {
        byte[] out = new byte[2 + l2.length];
        out[0] = (byte) (msgId >> 8);
        out[1] = (byte) msgId;
        System.arraycopy(l2, 0, out, 2, l2.length);
        return out;
    }

    @Test
    void bootstrapHelloThenSealedOpsOverHttp() throws Exception {
        KeyPair wallet = KeyPairGenerator.getInstance("X25519").generateKeyPair();
        byte[] walletPub = rawPub(wallet);

        // 1. Bootstrap HELLO (plaintext) over HTTPS.
        Envelope helloReq = Ops.helloRequest(1, walletPub, new int[]{Op.HELLO, Op.KEYSETS, Op.KEYS, Op.CHECKSTATE});
        byte[] helloResp = mvc().perform(post(MeshuHttpController.PATH)
                        .contentType(MediaType.APPLICATION_OCTET_STREAM)
                        .content(body(1, L2.bootstrap(helloReq.encode()))))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsByteArray();

        // Response: msg_id(2) ‖ sealed L2. Strip msg_id.
        assertEquals(1, ((helloResp[0] & 0xFF) << 8) | (helloResp[1] & 0xFF));
        byte[] sealedHello = Arrays.copyOfRange(helloResp, 2, helloResp.length);

        // Wallet opens the HELLO response under k_g2w.
        KeyAgreement.DirectionalKeys keys = KeyAgreement.derive(wallet.getPrivate(), pairing.daemonPublicKey());
        byte[] helloL3 = L2.open(keys.gatewayToWallet(), L2.DIR_G2W, 1, Op.responseOf(Op.HELLO), sealedHello);
        Ops.HelloResponse hello = Ops.parseHelloResponse(Envelope.decode(helloL3));
        assertEquals("https://mint.test/Bitcoin", hello.mintUrls().get(0));

        // 2. KEYSETS, sealed wallet→gateway.
        int msgId = 2;
        byte[] sealedKeysets = L2.seal(keys.walletToGateway(), 0, L2.DIR_W2G, msgId, Op.KEYSETS,
                Ops.keysetsRequest(0).encode());
        byte[] keysetsResp = mvc().perform(post(MeshuHttpController.PATH)
                        .contentType(MediaType.APPLICATION_OCTET_STREAM)
                        .content(body(msgId, sealedKeysets)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsByteArray();
        byte[] keysetsL3 = L2.open(keys.gatewayToWallet(), L2.DIR_G2W, msgId, Op.responseOf(Op.KEYSETS),
                Arrays.copyOfRange(keysetsResp, 2, keysetsResp.length));
        List<Ops.KeysetEntry> keysets = Ops.parseKeysetsResponse(Envelope.decode(keysetsL3));
        assertEquals(1, keysets.size());
        assertTrue(keysets.get(0).active());

        // 3. CHECKSTATE, sealed.
        msgId = 3;
        byte[] y = new byte[33];
        Arrays.fill(y, (byte) 7);
        byte[] sealedCheck = L2.seal(keys.walletToGateway(), 0, L2.DIR_W2G, msgId, Op.CHECKSTATE,
                Ops.checkstateRequest(List.of(y)).encode());
        byte[] checkResp = mvc().perform(post(MeshuHttpController.PATH)
                        .contentType(MediaType.APPLICATION_OCTET_STREAM)
                        .content(body(msgId, sealedCheck)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsByteArray();
        byte[] checkL3 = L2.open(keys.gatewayToWallet(), L2.DIR_G2W, msgId, Op.responseOf(Op.CHECKSTATE),
                Arrays.copyOfRange(checkResp, 2, checkResp.length));
        int[] states = Ops.parseCheckstateResponse(Envelope.decode(checkL3), 1);
        assertArrayEquals(new int[]{Ops.STATE_UNSPENT}, states);
    }

    @Test
    void exactRetryOverHttpIsIdempotent() throws Exception {
        KeyPair wallet = KeyPairGenerator.getInstance("X25519").generateKeyPair();
        byte[] walletPub = rawPub(wallet);
        mvc().perform(post(MeshuHttpController.PATH).contentType(MediaType.APPLICATION_OCTET_STREAM)
                .content(body(10, L2.bootstrap(Ops.helloRequest(1, walletPub, new int[]{Op.HELLO}).encode()))))
                .andExpect(status().isOk());

        KeyAgreement.DirectionalKeys keys = KeyAgreement.derive(wallet.getPrivate(), pairing.daemonPublicKey());
        byte[] sealed = L2.seal(keys.walletToGateway(), 0, L2.DIR_W2G, 11, Op.KEYSETS,
                Ops.keysetsRequest(0).encode());

        byte[] r1 = mvc().perform(post(MeshuHttpController.PATH).contentType(MediaType.APPLICATION_OCTET_STREAM)
                .content(body(11, sealed))).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsByteArray();
        byte[] r2 = mvc().perform(post(MeshuHttpController.PATH).contentType(MediaType.APPLICATION_OCTET_STREAM)
                .content(body(11, sealed))).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsByteArray();
        assertArrayEquals(r1, r2); // identical sealed response from the replay cache
    }

    @Test
    void tooShortBodyIsRejected() throws Exception {
        mvc().perform(post(MeshuHttpController.PATH)
                        .contentType(MediaType.APPLICATION_OCTET_STREAM)
                        .content(new byte[]{0x00}))
                .andExpect(status().isBadRequest());
    }

    @Test
    void unverifiableMessageIsUnauthorized() throws Exception {
        // Garbage sealed bytes → no pinned key opens it → 401 (DECRYPT_FAILED).
        KeyPair stranger = KeyPairGenerator.getInstance("X25519").generateKeyPair();
        KeyAgreement.DirectionalKeys keys = KeyAgreement.derive(stranger.getPrivate(), pairing.daemonPublicKey());
        byte[] sealed = L2.seal(keys.walletToGateway(), 0, L2.DIR_W2G, 99, Op.KEYSETS,
                Ops.keysetsRequest(0).encode());
        mvc().perform(post(MeshuHttpController.PATH)
                        .contentType(MediaType.APPLICATION_OCTET_STREAM)
                        .content(body(99, sealed)))
                .andExpect(status().isUnauthorized());
    }
}
