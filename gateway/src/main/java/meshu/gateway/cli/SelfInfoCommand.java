package meshu.gateway.cli;

import meshu.gateway.companion.MeshCoreNode;
import meshu.gateway.companion.SelfInfo;
import meshu.gateway.config.GatewayProperties;
import meshu.gateway.crypto.DaemonIdentity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;

/**
 * {@code java -jar gateway.jar self-info} — read the gateway node's identity
 * over USB and print everything that goes into the connection QR
 * (POC-WALLET.md §8): the node's Ed25519 pubkey, the daemon's X25519 pubkey
 * (generated on first run), and the combined fingerprint.
 */
@Component
public class SelfInfoCommand implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(SelfInfoCommand.class);
    private static final Duration RESPONSE_TIMEOUT = Duration.ofSeconds(5);

    private final GatewayProperties props;
    private final DaemonIdentity daemonIdentity;

    public SelfInfoCommand(GatewayProperties props, DaemonIdentity daemonIdentity) {
        this.props = props;
        this.daemonIdentity = daemonIdentity;
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {
        if (!args.getNonOptionArgs().contains("self-info")) {
            return;
        }

        String port = props.serial().port();
        if (port == null || port.isBlank()) {
            List<String> candidates = MeshCoreNode.detectPorts();
            if (candidates.isEmpty()) {
                throw new IllegalStateException(
                        "no serial port configured (meshu.serial.port) and no usbmodem/usbserial device found");
            }
            if (candidates.size() > 1) {
                throw new IllegalStateException(
                        "multiple candidate serial ports " + candidates + " — set meshu.serial.port");
            }
            port = candidates.getFirst();
        }

        try (MeshCoreNode node = MeshCoreNode.open(port, props.serial().baud())) {
            SelfInfo info = node.appStart("meshu-gw", RESPONSE_TIMEOUT);
            KeyPair daemonKey = daemonIdentity.loadOrCreate();
            byte[] x25519Pub = DaemonIdentity.rawPublicKey(daemonKey);

            HexFormat hex = HexFormat.of();
            System.out.println();
            System.out.println("=== MeshCore node (radio identity) ===");
            System.out.println("  port            : " + port);
            System.out.println("  node name       : " + info.name());
            System.out.println("  ed25519 pubkey  : " + hex.formatHex(info.publicKey()));
            System.out.printf("  radio           : %.3f MHz / %.1f kHz / SF%d / CR%d%n",
                    info.radioFreqMhz(), info.radioBwKhz(), info.radioSf(), info.radioCr());
            System.out.println("  tx power        : " + info.txPower() + " (max " + info.maxTxPower() + ")");
            System.out.println();
            System.out.println("=== Gateway daemon (L2 identity, POC-WALLET.md §8.1) ===");
            System.out.println("  x25519 pubkey   : " + hex.formatHex(x25519Pub));
            System.out.println();
            System.out.println("=== Connection QR inputs (POC-WALLET.md §8) ===");
            System.out.println("  fingerprint     : "
                    + DaemonIdentity.fingerprint(info.publicKey(), x25519Pub));
            System.out.println("  mint url        : " + props.mint().url());
        }
    }
}
