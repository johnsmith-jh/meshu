/**
 * L1 frame kinds (PROTOCOL.md §3.1). On-wire first byte is VVKKKKKK:
 * version (top 2 bits, 0b00 for v1) ‖ kind (low 6 bits). TS port of FrameKind.
 */
export const KIND_DATA = 0x10;
export const KIND_ACKBM = 0x12;
export const KIND_NACK = 0x13;
export const KIND_ABORT = 0x14;
export const KIND_PING = 0x15;

/** NACK / ABORT reason codes (§3.8). */
export const REASON_UNSUPPORTED_VERSION = 0x01;
export const REASON_MSG_TOO_LARGE = 0x02;
export const REASON_DECRYPT_FAILED = 0x03;
export const REASON_REASM_TIMEOUT = 0x04;
export const REASON_BUSY = 0x05;
export const REASON_MALFORMED = 0x06;
