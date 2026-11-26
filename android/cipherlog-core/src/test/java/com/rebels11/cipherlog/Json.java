package com.rebels11.cipherlog;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** A minimal JSON parser for the vectors (objects, arrays, strings, numbers, booleans, null). Tests only. */
final class Json {
    private final String s;
    private int i;

    private Json(String s) {
        this.s = s;
    }

    static Object parse(String text) {
        Json json = new Json(text);
        Object value = json.value();
        json.space();
        if (json.i != text.length()) throw new IllegalArgumentException("trailing JSON at " + json.i);
        return value;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> obj(Object value) {
        return (Map<String, Object>) value;
    }

    @SuppressWarnings("unchecked")
    static List<Object> arr(Object value) {
        return (List<Object>) value;
    }

    private void space() {
        while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
    }

    private Object value() {
        space();
        char c = s.charAt(i);
        if (c == '{') {
            i++;
            Map<String, Object> out = new LinkedHashMap<>();
            space();
            if (s.charAt(i) == '}') {
                i++;
                return out;
            }
            while (true) {
                space();
                String key = string();
                space();
                expect(':');
                out.put(key, value());
                space();
                if (s.charAt(i) == ',') {
                    i++;
                    continue;
                }
                expect('}');
                return out;
            }
        }
        if (c == '[') {
            i++;
            List<Object> out = new ArrayList<>();
            space();
            if (s.charAt(i) == ']') {
                i++;
                return out;
            }
            while (true) {
                out.add(value());
                space();
                if (s.charAt(i) == ',') {
                    i++;
                    continue;
                }
                expect(']');
                return out;
            }
        }
        if (c == '"') return string();
        if (s.startsWith("true", i)) {
            i += 4;
            return Boolean.TRUE;
        }
        if (s.startsWith("false", i)) {
            i += 5;
            return Boolean.FALSE;
        }
        if (s.startsWith("null", i)) {
            i += 4;
            return null;
        }
        int start = i;
        while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) i++;
        String number = s.substring(start, i);
        if (number.contains(".") || number.contains("e") || number.contains("E")) return Double.parseDouble(number);
        return Long.parseLong(number);
    }

    private void expect(char c) {
        if (s.charAt(i) != c) throw new IllegalArgumentException("expected " + c + " at " + i);
        i++;
    }

    private String string() {
        expect('"');
        StringBuilder out = new StringBuilder();
        while (true) {
            char c = s.charAt(i++);
            if (c == '"') return out.toString();
            if (c != '\\') {
                out.append(c);
                continue;
            }
            char e = s.charAt(i++);
            switch (e) {
                case 'n': out.append('\n'); break;
                case 't': out.append('\t'); break;
                case 'r': out.append('\r'); break;
                case 'b': out.append('\b'); break;
                case 'f': out.append('\f'); break;
                case 'u':
                    out.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                    i += 4;
                    break;
                default: out.append(e);
            }
        }
    }
}
