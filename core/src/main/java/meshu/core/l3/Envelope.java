package meshu.core.l3;

import java.util.List;

/**
 * The L3 message envelope (PROTOCOL.md §5.2): a CBOR array whose first element
 * is the opcode. Decoders ignore unknown trailing array elements for forward
 * compatibility (§5.2, §13.2).
 */
public record Envelope(int opcode, List<Cbor.Value> fields) {

    public Envelope {
        if (opcode < 0 || opcode > 0xFF) {
            throw new IllegalArgumentException("opcode out of range: " + opcode);
        }
        fields = List.copyOf(fields);
    }

    public static Envelope of(int opcode, Cbor.Value... fields) {
        return new Envelope(opcode, List.of(fields));
    }

    /** Encode to CBOR: [opcode, field1, field2, ...] */
    public byte[] encode() {
        java.util.ArrayList<Cbor.Value> items = new java.util.ArrayList<>(fields.size() + 1);
        items.add(Cbor.uint(opcode));
        items.addAll(fields);
        return Cbor.encode(Cbor.array(items));
    }

    /**
     * Decode from CBOR. The opcode is the first <em>element</em> of the array
     * (§4.5's opcode_hint), not the first byte (which is the array header).
     */
    public static Envelope decode(byte[] data) {
        Cbor.Value v = Cbor.decode(data);
        if (!(v instanceof Cbor.Value.Array a) || a.items().isEmpty()) {
            throw new IllegalArgumentException("L3 message must be a non-empty CBOR array");
        }
        if (!(a.items().getFirst() instanceof Cbor.Value.Uint op)) {
            throw new IllegalArgumentException("first array element must be the opcode (uint)");
        }
        int opcode = op.intValue();
        return new Envelope(opcode, a.items().subList(1, a.items().size()));
    }

    /**
     * The opcode hint used in the L2 AEAD associated data (§4.5): the first
     * <em>element</em>, already the opcode — this just makes the intent explicit.
     */
    public int opcodeHint() {
        return opcode;
    }
}
