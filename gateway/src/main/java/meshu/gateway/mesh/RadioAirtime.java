package meshu.gateway.mesh;

/**
 * LoRa time-on-air for one full-size frame, per the Semtech formula
 * (TESTVECTORS.md §11): explicit header, CR 4/5, 8-symbol preamble, CRC on,
 * low-data-rate optimisation for SF ≥ 11. Used to seed the airtime governor
 * from live SELF_INFO parameters (§12.1) instead of hardcoding the default.
 */
public final class RadioAirtime {

    private RadioAirtime() {
    }

    /** Airtime of a 181-byte raw packet in ms. */
    public static long frameAirtimeMs(int sf, int bwKhz) {
        double bw = bwKhz * 1000.0;
        int de = sf >= 11 ? 1 : 0;
        double tsym = Math.pow(2, sf) / bw;
        int payload = 181;
        int crc = 1, ih = 0, cr = 1, preamble = 8;
        double num = 8.0 * payload - 4.0 * sf + 28 + 16.0 * crc - 20.0 * ih;
        double den = 4.0 * (sf - de);
        int n = 8 + (int) Math.max(0, Math.ceil(num / den) * (cr + 4));
        double ms = ((preamble + 4.25) * tsym + n * tsym) * 1000.0;
        return Math.round(ms);
    }
}
