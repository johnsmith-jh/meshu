package meshu.gateway.mesh;

import meshu.gateway.companion.MeshCoreNode;
import meshu.gateway.companion.PacketType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.function.Consumer;

/**
 * {@link RawDatagramRadio} over a real companion node (zero-hop: §2.6 path_len 0).
 *
 * <p>Inbound pushes arrive as full companion payloads
 * {@code [0x84 ‖ SNR(s8) ‖ RSSI(s8) ‖ 0xFF ‖ payload]} — the 4-byte prefix is
 * stripped here (payload begins at offset 4 with NO length byte, §2.5), so the
 * mesh layer sees exactly {@code dst ‖ src ‖ L1 frame}. TABLE_FULL surfaces as
 * {@link RadioBusyException}; everything else as a generic failure.
 */
public final class MeshCoreRadio implements RawDatagramRadio {

    private static final Logger log = LoggerFactory.getLogger(MeshCoreRadio.class);

    private static final Duration SEND_TIMEOUT = Duration.ofSeconds(5);
    /** SNR + RSSI + reserved byte precede the raw payload (§2.5). */
    private static final int PUSH_HEADER_LEN = 4;

    private final MeshCoreNode node;

    public MeshCoreRadio(MeshCoreNode node) {
        this.node = node;
        // RF log visibility (Dispatcher::logRxRaw): the node pushes one frame
        // per packet its radio HEARS — pre-everything, including packets that
        // are later dropped. Decoding it shows link quality (RSSI/SNR) of the
        // wallet node's transmissions and ambient traffic.
        node.onPush(PacketType.Push.LOG_RX_DATA, frame -> {
            if (frame.length < 4) {
                return;
            }
            int snrRaw = frame[1];
            double snr = (snrRaw > 127 ? snrRaw - 256 : snrRaw) / 4.0;
            int rssiRaw = frame[2] & 0xFF;
            int rssi = rssiRaw > 127 ? rssiRaw - 256 : rssiRaw;
            int hdr = frame[3] & 0xFF;
            int type = (hdr >> 2) & 0xF;
            log.info("RF rx (node): type=0x{} snr={} dB rssi={} dBm len={}",
                    Integer.toHexString(type), String.format("%.1f", snr), rssi, frame.length - 3);
        });
    }

    @Override
    public void onReceive(Consumer<byte[]> handler) {
        node.onPush(PacketType.Push.RAW_DATA, frame -> {
            if (frame.length <= PUSH_HEADER_LEN) {
                log.info("raw push too short ({} B) — ignored", frame.length);
                return;
            }
            byte[] payload = new byte[frame.length - PUSH_HEADER_LEN];
            System.arraycopy(frame, PUSH_HEADER_LEN, payload, 0, payload.length);
            log.info("raw push in: {} B  dst=0x{} src=0x{} kind=0x{}",
                    payload.length,
                    Integer.toHexString(payload[0] & 0xFF),
                    Integer.toHexString(payload[1] & 0xFF),
                    Integer.toHexString((payload[2] & 0x3F)));
            handler.accept(payload);
        });
    }

    @Override
    public void send(byte[] payload) throws RadioException {
        try {
            MeshCoreNode.RawSendResult r = node.sendRawData(0, new byte[0], payload, SEND_TIMEOUT);
            if (r.sent()) {
                log.info("raw send: node accepted {} B  dst=0x{} src=0x{} kind=0x{}",
                        payload.length,
                        Integer.toHexString(payload[0] & 0xFF),
                        Integer.toHexString(payload[1] & 0xFF),
                        Integer.toHexString((payload[2] & 0x3F)));
                return;
            }
            if (r.tableFull()) {
                log.info("raw send: node queue FULL — will back off (§2.8)");
                throw new RadioBusyException();
            }
            log.warn("raw send: node rejected — ERR_CODE={}", r.errCode());
            throw new RadioException("SEND_RAW_DATA failed, ERR_CODE=" + r.errCode());
        } catch (java.util.concurrent.TimeoutException e) {
            log.warn("raw send: no OK/ERR from node within {}", SEND_TIMEOUT);
            throw new RadioException("SEND_RAW_DATA timed out", e);
        } catch (java.io.IOException e) {
            throw new RadioException("serial I/O during SEND_RAW_DATA", e);
        }
    }
}
