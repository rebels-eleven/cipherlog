package com.rebels11.cipherlog;

import java.util.List;

/**
 * One source of device-block lines (SPEC.md 2.5). Every new file starts with {@code <name> · <line>} for each line it
 * gives. A collector that throws gives {@code <name> · failed <error type name>}; the others still run.
 *
 * <p>Collectors run on the writer's worker thread and must be thread-safe and fast. They must not wait for the main
 * thread: the main thread may be waiting for the writer ({@code wipe}, {@code exportBundle}), and such a wait then
 * lasts until that call times out. Their lines pass through the config's {@code scrub} hook.
 */
public interface CipherLogCollector {
    /** The name printed before each line, for example {@code system} or {@code app}. */
    String name();

    /** Zero or more lines; may throw. */
    List<String> lines() throws Exception;

    /** The lines of a collector made with {@link #of(String, Source)}. */
    interface Source {
        /** Zero or more lines; may throw. */
        List<String> lines() throws Exception;
    }

    /** A collector from a name and a function. */
    static CipherLogCollector of(final String name, final Source source) {
        if (name == null || source == null) throw new IllegalArgumentException("name and source are required");
        return new CipherLogCollector() {
            @Override
            public String name() {
                return name;
            }

            @Override
            public List<String> lines() throws Exception {
                return source.lines();
            }
        };
    }
}
