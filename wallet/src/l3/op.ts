/**
 * MeshCash operation codes (PROTOCOL.md §7). Requests 0x00–0x7F;
 * response = 0x80 | request. TS port of core/Op.java.
 */
export const MINT_QUOTE = 0x01;
export const MINT_QUOTE_STATE = 0x02;
export const MINT = 0x03;
export const MELT_QUOTE = 0x04;
export const MELT = 0x05;
export const MELT_QUOTE_STATE = 0x06;
export const RESTORE = 0x07;
export const SWAP = 0x08;
export const CHECKSTATE = 0x09;
export const KEYSETS = 0x0a;
export const KEYS = 0x0b;
export const MINT_INFO = 0x0c;
export const HELLO = 0x0d;
export const ERROR = 0xfe;

export function responseOf(requestOp: number): number {
  if (requestOp < 0x01 || requestOp > 0x7f) {
    throw new Error(`not a request opcode: 0x${requestOp.toString(16)}`);
  }
  return 0x80 | requestOp;
}

/** Gateway transport-level error codes (§10.3). */
export const MC_UNSUPPORTED_OP = 0xf001;
export const MC_MALFORMED = 0xf002;
export const MC_STALE_HANDLE = 0xf003;
export const MC_MINT_UNREACHABLE = 0xf004;
export const MC_MINT_TIMEOUT = 0xf005;
export const MC_RATE_LIMITED = 0xf006;
