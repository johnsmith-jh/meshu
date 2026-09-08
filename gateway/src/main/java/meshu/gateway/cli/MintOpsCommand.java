package meshu.gateway.cli;

import meshu.core.l3.Envelope;
import meshu.core.l3.Ops;
import meshu.gateway.config.GatewayProperties;
import meshu.gateway.mint.MintClient;
import meshu.gateway.ops.OpDispatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * {@code java -jar gateway.jar mint-ops} — exercise the read-only ops
 * (KEYSETS, KEYS, MINT_INFO) against the configured mint over HTTPS and print
 * the decoded results. A vertical-slice check that the dispatcher + MintClient
 * + core codecs work end to end against a real mint, no radio involved.
 */
@Component
public class MintOpsCommand implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(MintOpsCommand.class);

    private final GatewayProperties props;

    public MintOpsCommand(GatewayProperties props) {
        this.props = props;
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {
        if (!args.getNonOptionArgs().contains("mint-ops")) {
            return;
        }

        String mintUrl = props.mint().url();
        MintClient mint = new MintClient(mintUrl);
        OpDispatcher.SessionState session = new OpDispatcher.SessionState();
        session.mintUrls.add(mintUrl);
        OpDispatcher dispatcher = new OpDispatcher(mint, session);

        System.out.println();
        System.out.println("=== mint: " + mintUrl + " ===");

        // KEYSETS (§8.10)
        Envelope keysetsResp = dispatcher.dispatch(Ops.keysetsRequest(0));
        List<Ops.KeysetEntry> keysets = Ops.parseKeysetsResponse(keysetsResp);
        System.out.println("\nKEYSETS (" + keysets.size() + "):");
        for (int i = 0; i < keysets.size(); i++) {
            Ops.KeysetEntry k = keysets.get(i);
            System.out.printf("  [%d] s_id=%s unit=%s active=%s fee_ppk=%d expiry=%d%n",
                    i, hex(k.shortId()), k.unit(), k.active(), k.inputFeePpk(), k.finalExpiry());
        }

        // KEYS for the first active keyset, ranged 0..16 (§8.11)
        int activeHandle = -1;
        for (int i = 0; i < keysets.size(); i++) {
            if (keysets.get(i).active()) {
                activeHandle = i;
                break;
            }
        }
        if (activeHandle >= 0) {
            Envelope keysResp = dispatcher.dispatch(Ops.keysRequest(activeHandle, 0, 16));
            byte[] blob = ((meshu.core.l3.Cbor.Value.Bytes) keysResp.fields().get(1)).value();
            List<byte[]> keys = meshu.core.l3.PackedBlobs.unpackSignatures(blob);
            System.out.println("\nKEYS handle " + activeHandle + " (exponents 0..16): " + keys.size() + " keys");
            System.out.println("  2^0 key: " + hex(keys.get(0)));
            System.out.println("  2^16 key: " + hex(keys.get(keys.size() - 1)));
        } else {
            System.out.println("\nKEYS: no active keyset found");
        }

        // MINT_INFO (§8.12)
        Envelope infoResp = dispatcher.dispatch(Ops.mintInfoRequest(0));
        System.out.println("\nMINT_INFO (raw projected): " +
                ((meshu.core.l3.Cbor.Value.Text) infoResp.fields().get(0)).value());
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(Character.forDigit((x >> 4) & 0xF, 16)).append(Character.forDigit(x & 0xF, 16));
        }
        return sb.toString();
    }
}
