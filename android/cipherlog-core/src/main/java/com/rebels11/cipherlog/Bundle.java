package com.rebels11.cipherlog;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** The bundle container (SPEC.md 4): {@code CPB1} ‖ entries of {@code len} (u32) ‖ file bytes. */
final class Bundle {
    private Bundle() {
    }

    static byte[] encode(List<byte[]> files) {
        int size = Format.BUNDLE_MAGIC.length;
        for (byte[] file : files) size += 4 + file.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream(size);
        out.write(Format.BUNDLE_MAGIC, 0, 4);
        for (byte[] file : files) {
            out.write(Format.u32(file.length), 0, 4);
            out.write(file, 0, file.length);
        }
        return out.toByteArray();
    }

    /** The entries; a length that runs past the end, or fewer than 4 bytes left for a length, ends it with a note. */
    static List<byte[]> split(byte[] bytes, List<String> notes) {
        List<byte[]> entries = new ArrayList<>();
        int offset = Format.BUNDLE_MAGIC.length;
        while (offset < bytes.length) {
            if (bytes.length - offset < 4) {
                notes.add("bad entry length after entry " + entries.size() + ", bundle ends");
                break;
            }
            long len = Format.readU32(bytes, offset);
            if (len > bytes.length - offset - 4L) {
                notes.add("bad entry length after entry " + entries.size() + ", bundle ends");
                break;
            }
            entries.add(Arrays.copyOfRange(bytes, offset + 4, offset + 4 + (int) len));
            offset += 4 + (int) len;
        }
        return entries;
    }
}
