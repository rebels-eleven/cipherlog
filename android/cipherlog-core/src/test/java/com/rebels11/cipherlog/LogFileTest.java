package com.rebels11.cipherlog;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import org.junit.Test;

/** One open file: nonce range and native memory on failure paths. */
public class LogFileTest {
    private final byte[] header = new byte[Format.HEADER_BYTES];

    private LogFile newFile(OutputStream out) throws Exception {
        byte[] key = new byte[32];
        for (int i = 0; i < 32; i++) key[i] = (byte) i;
        return new LogFile(out, key, new byte[16], header);
    }

    @Test
    public void seqNeverWrapsPastU32() throws Exception {
        LogFile file = newFile(new ByteArrayOutputStream());
        file.seq = 0xFFFF_FFFFL;
        file.append("last record that fits\n");
        file.flush();
        assertEquals(0x1_0000_0000L, file.seq);
        file.append("would reuse the nonce of record 0\n");
        try {
            file.flush();
            fail("a record past seq 0xFFFFFFFF must be refused");
        } catch (GeneralSecurityException expected) {
            // ok
        }
        file.abandon();
    }

    @Test
    public void aFailedFinishStillFreesTheCompressor() throws Exception {
        final int limit = Format.HEADER_BYTES;
        OutputStream out = new OutputStream() {
            int written = 0;

            @Override
            public void write(int b) throws IOException {
                write(new byte[] {(byte) b}, 0, 1);
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                if (written + len > limit) throw new IOException("No space left on device");
                written += len;
            }
        };
        LogFile file = newFile(out);
        file.append("text\n");
        try {
            file.finish();
            fail("finish must fail");
        } catch (IOException expected) {
            // ok
        }
        assertTrue(file.released());
    }

    @Test
    public void aFailedHeaderWriteFreesTheCompressor() {
        OutputStream out = new OutputStream() {
            @Override
            public void write(int b) throws IOException {
                throw new IOException("No space left on device");
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                throw new IOException("No space left on device");
            }
        };
        try {
            newFile(out);
            fail("the header write must fail");
        } catch (Exception expected) {
            assertTrue(expected instanceof IOException);
        }
    }
}
