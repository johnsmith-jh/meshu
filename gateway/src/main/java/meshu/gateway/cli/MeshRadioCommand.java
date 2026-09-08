package meshu.gateway.cli;

import meshu.core.l1.AirtimeGovernor;
import meshu.core.l1.MessageSender;
import meshu.gateway.companion.MeshCoreNode;
import meshu.gateway.companion.SelfInfo;
import meshu.gateway.config.GatewayProperties;
import meshu.gateway.mesh.MeshCoreRadio;
import meshu.gateway.mesh.MeshGateway;
import meshu.gateway.mesh.RadioAirtime;
import meshu.gateway.session.SessionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.CountDownLatch;

/**
 * {@code java -jar gateway.jar mesh-radio} — run the daemon's mesh transport
 * against the tethered companion node (PROTOCOL.md §2). Serves inbound raw
 * datagrams through {@code SessionService}; HTTPS stays up alongside.
 *
 * <p>Bench bring-up: with both nodes powered, a PING frame addressed to this
 * node's hash should echo back; a bootstrap HELLO from node#2's side gets a
 * sealed reply over the air.
 */
@Component
public class MeshRadioCommand implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(MeshRadioCommand.class);

    private final GatewayProperties props;
    private final SessionService session;

    public MeshRadioCommand(GatewayProperties props, SessionService session) {
        this.props = props;
        this.session = session;
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {
        if (!args.getNonOptionArgs().contains("mesh-radio")) {
            return;
        }

        String port = resolvePort();
        int baud = props.serial().baud();

        try (MeshCoreNode node = MeshCoreNode.open(port, baud)) {
            // APP_START also yields our node identity → self hash (§2.2).
            SelfInfo selfInfo = node.appStart("meshu-gw", Duration.ofSeconds(5));
            byte selfHash = selfInfo.publicKey()[0];
            log.info("node {} hash 0x{} radio {} MHz BW{} SF{}",
                    selfInfo.name(), Integer.toHexString(selfHash & 0xFF),
                    selfInfo.radioFreqMhz(), Math.round(selfInfo.radioBwKhz()), selfInfo.radioSf());

            // Airtime per §12.1: compute from live SELF_INFO parameters.
            long airtimeMs = RadioAirtime.frameAirtimeMs(
                    selfInfo.radioSf(), (int) Math.round(selfInfo.radioBwKhz()));
            AirtimeGovernor governor = AirtimeGovernor.withDefaults(airtimeMs);
            MessageSender.Config cfg = MessageSender.Config.defaults(airtimeMs);

            MeshCoreRadio radio = new MeshCoreRadio(node);
            MeshGateway gateway = new MeshGateway(radio, session, governor, selfHash, cfg);
            gateway.start();

            log.info("mesh gateway up on hash 0x{} — Ctrl-C to stop",
                    Integer.toHexString(selfHash & 0xFF));
            new CountDownLatch(1).await(); // block until process exit
        }
    }

    private String resolvePort() {
        String port = props.serial().port();
        if (port != null && !port.isBlank()) {
            return port;
        }
        List<String> candidates = MeshCoreNode.detectPorts();
        if (candidates.isEmpty()) {
            throw new IllegalStateException("no serial port for mesh-radio (set meshu.serial.port)");
        }
        if (candidates.size() > 1) {
            throw new IllegalStateException("multiple candidate ports " + candidates
                    + " — set meshu.serial.port");
        }
        return candidates.getFirst();
    }
}
