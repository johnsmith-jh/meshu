package meshu.gateway.mint;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal JSON parser for mint responses — just enough to read the Cashu API
 * (objects, arrays, strings, numbers, booleans, null). Deliberately tiny; the
 * gateway only ever parses mint-produced JSON, which is well-formed.
 */
final class Json {

    private Json() {
    }

    sealed interface Value {
        record Obj(Object object) implements Value {
            @Override
            public Object asObject() {
                return object;
            }
        }

        record Arr(List<Value> items) implements Value {
        }

        record Str(String value) implements Value {
        }

        record Num(String raw) implements Value {
        }

        record Bool(boolean value) implements Value {
        }

        enum Null implements Value {INSTANCE}

        default Object asObject() {
            throw new IllegalStateException("not an object");
        }

        default String asString() {
            return ((Str) this).value;
        }
    }

    static final class Object {
        private final Map<String, Value> map = new LinkedHashMap<>();

        void put(String key, Value v) {
            map.put(key, v);
        }

        java.util.Set<Map.Entry<String, Value>> entrySet() {
            return map.entrySet();
        }

        Value get(String key) {
            Value v = map.get(key);
            if (v == null) {
                throw new IllegalArgumentException("missing JSON key: " + key);
            }
            return v;
        }

        boolean isNull(String key) {
            return map.get(key) instanceof Value.Null || !map.containsKey(key);
        }

        String getString(String key) {
            return ((Value.Str) get(key)).value();
        }

        boolean getBool(String key) {
            return ((Value.Bool) get(key)).value();
        }

        long getLong(String key) {
            return Long.parseLong(((Value.Num) get(key)).raw());
        }

        long optLong(String key, long def) {
            Value v = map.get(key);
            return v instanceof Value.Num n ? Long.parseLong(n.raw()) : def;
        }

        List<Value> getArray(String key) {
            return ((Value.Arr) get(key)).items();
        }

        Object getObject(String key) {
            return ((Value.Obj) get(key)).object();
        }
    }

    static Object parseObject(String json) {
        Parser p = new Parser(json);
        p.skipWs();
        Object o = p.parseObject();
        p.skipWs();
        return o;
    }

    private static final class Parser {
        private final String s;
        private int i;

        Parser(String s) {
            this.s = s;
        }

        void skipWs() {
            while (i < s.length() && Character.isWhitespace(s.charAt(i))) {
                i++;
            }
        }

        Object parseObject() {
            expect('{');
            Object obj = new Object();
            skipWs();
            if (peek() == '}') {
                i++;
                return obj;
            }
            while (true) {
                skipWs();
                String key = parseString();
                skipWs();
                expect(':');
                skipWs();
                obj.put(key, parseValue());
                skipWs();
                char c = s.charAt(i++);
                if (c == '}') {
                    break;
                }
                if (c != ',') {
                    throw new IllegalArgumentException("expected , or } at " + i);
                }
            }
            return obj;
        }

        private Value parseValue() {
            skipWs();
            char c = peek();
            return switch (c) {
                case '{' -> new Value.Obj(parseObject());
                case '[' -> parseArray();
                case '"' -> new Value.Str(parseString());
                case 't' -> {
                    expectWord("true");
                    yield new Value.Bool(true);
                }
                case 'f' -> {
                    expectWord("false");
                    yield new Value.Bool(false);
                }
                case 'n' -> {
                    expectWord("null");
                    yield Value.Null.INSTANCE;
                }
                default -> parseNumber();
            };
        }

        private Value parseArray() {
            expect('[');
            List<Value> items = new ArrayList<>();
            skipWs();
            if (peek() == ']') {
                i++;
                return new Value.Arr(items);
            }
            while (true) {
                skipWs();
                items.add(parseValue());
                skipWs();
                char c = s.charAt(i++);
                if (c == ']') {
                    break;
                }
                if (c != ',') {
                    throw new IllegalArgumentException("expected , or ] at " + i);
                }
            }
            return new Value.Arr(items);
        }

        private String parseString() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (true) {
                char c = s.charAt(i++);
                if (c == '"') {
                    break;
                }
                if (c == '\\') {
                    char esc = s.charAt(i++);
                    sb.append(switch (esc) {
                        case '"' -> '"';
                        case '\\' -> '\\';
                        case '/' -> '/';
                        case 'n' -> '\n';
                        case 't' -> '\t';
                        case 'r' -> '\r';
                        case 'b' -> '\b';
                        case 'f' -> '\f';
                        case 'u' -> {
                            String hex = s.substring(i, i + 4);
                            i += 4;
                            yield (char) Integer.parseInt(hex, 16);
                        }
                        default -> throw new IllegalArgumentException("bad escape \\" + esc);
                    });
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        }

        private Value parseNumber() {
            int start = i;
            while (i < s.length() && "-+0123456789.eE".indexOf(s.charAt(i)) >= 0) {
                i++;
            }
            return new Value.Num(s.substring(start, i));
        }

        private char peek() {
            return s.charAt(i);
        }

        private void expect(char c) {
            skipWs();
            if (s.charAt(i) != c) {
                throw new IllegalArgumentException("expected '" + c + "' at " + i);
            }
            i++;
        }

        private void expectWord(String w) {
            if (!s.startsWith(w, i)) {
                throw new IllegalArgumentException("expected " + w + " at " + i);
            }
            i += w.length();
        }
    }
}
