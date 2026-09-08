package meshu.gateway.ops;

import meshu.core.l3.Envelope;
import meshu.core.l3.Op;
import meshu.core.l3.Ops;
import meshu.core.l3.PackedBlobs;
import meshu.gateway.mint.MintClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Op dispatch: L3 envelope in → mint call → L3 envelope out. MintClient is
 * subclassed to stub the HTTP boundary.
 */
class OpDispatcherTest {

    private StubMint mint;
    private OpDispatcher.SessionState session;
    private OpDispatcher dispatcher;

    /** MintClient with the HTTP methods stubbed out. */
    static class StubMint extends MintClient {
        List<MintClient.KeysetInfo> keysets = new ArrayList<>();
        Map<Integer, byte[]> keys = new LinkedHashMap<>();
        List<ProofState> states = new ArrayList<>();
        List<BlindSignature> swapResult = new ArrayList<>();
        boolean swapCalled = false;

        StubMint() {
            super("https://mint.test/Bitcoin");
        }

        @Override
        public List<KeysetInfo> getKeysets() {
            return keysets;
        }

        @Override
        public Map<Integer, byte[]> getKeys(String keysetId) {
            return keys;
        }

        @Override
        public List<ProofState> checkState(List<byte[]> ys) {
            return states;
        }

        @Override
        public List<BlindSignature> swap(List<Proof> inputs, List<BlindedMessage> outputs) {
            swapCalled = true;
            return swapResult;
        }
    }

    private static byte[] fill(int len, int seed) {
        byte[] b = new byte[len];
        for (int i = 0; i < len; i++) {
            b[i] = (byte) (seed + i);
        }
        return b;
    }

    @BeforeEach
    void setup() {
        mint = new StubMint();
        session = new OpDispatcher.SessionState();
        session.mintUrls.add("https://mint.test/Bitcoin");
        dispatcher = new OpDispatcher(mint, session);
    }

    @Test
    void unsupportedOpReturnsError() throws Exception {
        Envelope resp = dispatcher.dispatch(Envelope.of(0x40, meshu.core.l3.Cbor.uint(1)));
        Ops.ErrorResponse err = Ops.parseError(resp);
        assertEquals(0xF001, err.code()); // MC_UNSUPPORTED_OP
    }

    @Test
    void keysetsPopulatesHandlesAndEntries() throws Exception {
        mint.keysets.add(new MintClient.KeysetInfo("00107937db0cc865", "sat", false, 0, null));
        mint.keysets.add(new MintClient.KeysetInfo("01fc0ec0e59cd6fa01b7a88f8cd77fce81fd1e64bca67d752e984992b7a3c3a821",
                "sat", true, 100, null));

        Envelope resp = dispatcher.dispatch(Ops.keysetsRequest(0));
        List<Ops.KeysetEntry> entries = Ops.parseKeysetsResponse(resp);
        assertEquals(2, entries.size());
        assertFalse(entries.get(0).active());
        assertTrue(entries.get(1).active());
        assertEquals(100, entries.get(1).inputFeePpk());
        // Handle 1 = the active keyset.
        assertEquals("01fc0ec0e59cd6fa01b7a88f8cd77fce81fd1e64bca67d752e984992b7a3c3a821",
                session.keysetIds.get(1));
        // shortId = first 8 bytes of full keyset ID.
        assertArrayEquals(MintClient.hex("01fc0ec0e59cd6fa"), entries.get(1).shortId());
    }

    @Test
    void nonZeroMintHandleRejectedAsStale() {
        assertThrows(OpDispatcher.StaleHandleException.class,
                () -> dispatcher.dispatch(Ops.keysetsRequest(1)));
    }

    @Test
    void keysRangeRequestReturnsOnlyRangedKeys() throws Exception {
        // Seed keyset handle table.
        mint.keysets.add(new MintClient.KeysetInfo("01fc0ec0e59cd6fa01b7a88f8cd77fce81fd1e64bca67d752e984992b7a3c3a821",
                "sat", true, 0, null));
        dispatcher.dispatch(Ops.keysetsRequest(0));
        // Stub the mint's keys: exponents 0..31.
        for (int e = 0; e < 32; e++) {
            mint.keys.put(e, fill(33, e));
        }
        Envelope resp = dispatcher.dispatch(Ops.keysRequest(0, 0, 16));
        byte[] blob = ((meshu.core.l3.Cbor.Value.Bytes) resp.fields().get(1)).value();
        List<byte[]> keys = PackedBlobs.unpackSignatures(blob);
        assertEquals(17, keys.size()); // exponents 0..16
        assertArrayEquals(fill(33, 0), keys.get(0));
        assertArrayEquals(fill(33, 16), keys.get(16));
    }

    @Test
    void unknownKeysetHandleIsStale() {
        assertThrows(OpDispatcher.StaleHandleException.class,
                () -> dispatcher.dispatch(Ops.keysRequest(5, 0, 16)));
    }

    @Test
    void checkstateMapsStatesToPacked() throws Exception {
        mint.states.add(MintClient.ProofState.UNSPENT);
        mint.states.add(MintClient.ProofState.PENDING);
        mint.states.add(MintClient.ProofState.SPENT);
        List<byte[]> ys = List.of(fill(33, 0), fill(33, 1), fill(33, 2));
        Envelope resp = dispatcher.dispatch(Ops.checkstateRequest(ys));
        int[] states = Ops.parseCheckstateResponse(resp, 3);
        assertArrayEquals(new int[]{Ops.STATE_UNSPENT, Ops.STATE_PENDING, Ops.STATE_SPENT}, states);
    }

    @Test
    void swapTranslatesExponentsAndReturnsSignatures() throws Exception {
        // Seed keyset.
        mint.keysets.add(new MintClient.KeysetInfo("01fc0ec0e59cd6fa01b7a88f8cd77fce81fd1e64bca67d752e984992b7a3c3a821",
                "sat", true, 0, null));
        dispatcher.dispatch(Ops.keysetsRequest(0));
        mint.swapResult.add(new MintClient.BlindSignature(2, "01fc…", fill(33, 9)));

        List<PackedBlobs.Proof> inputs = List.of(
                new PackedBlobs.Proof(3, fill(32, 0), fill(33, 32)));   // 8 sat
        List<PackedBlobs.Output> outputs = List.of(
                new PackedBlobs.Output(2, fill(33, 64)),                  // 4 sat
                new PackedBlobs.Output(1, fill(33, 97)));                 // 2 sat
        Envelope resp = dispatcher.dispatch(Ops.swapRequest(0, inputs, outputs));
        assertTrue(mint.swapCalled);
        List<byte[]> sigs = Ops.parseSwapResponse(resp);
        assertEquals(1, sigs.size());
        assertArrayEquals(fill(33, 9), sigs.get(0));
        assertEquals(Op.responseOf(Op.SWAP), resp.opcode());
    }
}
