package meshu.core.l3;

/**
 * Meshu operation codes (PROTOCOL.md §7). Requests are 0x00–0x7F; the
 * matching response is {@code 0x80 | request}.
 */
public final class Op {

    public static final int MINT_QUOTE = 0x01;
    public static final int MINT_QUOTE_STATE = 0x02;
    public static final int MINT = 0x03;
    public static final int MELT_QUOTE = 0x04;
    public static final int MELT = 0x05;
    public static final int MELT_QUOTE_STATE = 0x06;
    public static final int RESTORE = 0x07;
    public static final int SWAP = 0x08;
    public static final int CHECKSTATE = 0x09;
    public static final int KEYSETS = 0x0A;
    public static final int KEYS = 0x0B;
    public static final int MINT_INFO = 0x0C;
    public static final int HELLO = 0x0D;
    public static final int ERROR = 0xFE;

    private Op() {
    }

    /** Response opcode for a request opcode. */
    public static int responseOf(int requestOp) {
        if (requestOp < 0x01 || requestOp > 0x7F) {
            throw new IllegalArgumentException("not a request opcode: 0x%02x".formatted(requestOp));
        }
        return 0x80 | requestOp;
    }
}
