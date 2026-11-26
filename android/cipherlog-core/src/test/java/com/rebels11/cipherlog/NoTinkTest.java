package com.rebels11.cipherlog;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.Test;

/**
 * An app that excluded Tink (or ships a Tink without the internal classes) must get a writer that turns itself off with
 * one diagnostics line, never a crash. The library and {@link NoTinkProbe} are loaded again by a class loader that
 * cannot see any Tink class.
 */
public class NoTinkTest {
    @Test
    public void withoutTinkTheWriterTurnsOffWithOneLine() throws Exception {
        List<URL> urls = new ArrayList<>();
        for (String entry : System.getProperty("java.class.path").split(File.pathSeparator)) {
            if (entry.contains("tink")) continue;
            urls.add(new File(entry).toURI().toURL());
        }
        ClassLoader parent = ClassLoader.getPlatformClassLoader();
        try (URLClassLoader loader = new URLClassLoader(urls.toArray(new URL[0]), parent)) {
            try {
                loader.loadClass("com.google.crypto.tink.subtle.X25519");
                fail("Tink must be hidden");
            } catch (ClassNotFoundException expected) {
                // ok
            }
            Class<?> probe = loader.loadClass(NoTinkProbe.class.getName());
            assertTrue(probe.getClassLoader() == loader);
            Method run = probe.getMethod("run", File.class);
            @SuppressWarnings("unchecked")
            List<String> result = (List<String>) run.invoke(null, TestSupport.tempDir());
            // diagnostics, then isOn, then the number of files left behind.
            assertEquals(Arrays.asList("cipherlog off: crypto unavailable (NoClassDefFoundError)", "false", "0"),
                    result);
        }
    }
}
