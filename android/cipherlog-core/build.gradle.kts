// :cipherlog-core: the cipherlog-v1 writer and reader in plain Java (SPEC.md). No Android classes and no Kotlin: the
// same jar runs inside an Android app (minSdk 23) and on any JVM 11+.
import com.vanniktech.maven.publish.JavaLibrary
import com.vanniktech.maven.publish.JavadocJar
import com.vanniktech.maven.publish.SourcesJar

plugins {
    `java-library`
    alias(libs.plugins.maven.publish)
    alias(libs.plugins.animalsniffer)
}

group = providers.gradleProperty("GROUP").get()
version = providers.gradleProperty("VERSION_NAME").get()

tasks.withType<JavaCompile>().configureEach {
    // Java 11 bytecode and the Java 11 API only; the Android API level is checked by animalsniffer below.
    options.release.set(11)
    options.encoding = "UTF-8"
    options.compilerArgs.addAll(listOf("-Xlint:all,-serial,-options", "-Werror"))
}

tasks.withType<Javadoc>().configureEach {
    (options as StandardJavadocDocletOptions).apply {
        encoding = "UTF-8"
        addStringOption("Xdoclint:all,-missing", "-quiet")
    }
}

// The version string the device block prints, generated from gradle.properties (the single source).
val generateVersion by tasks.registering {
    val libraryVersion = version.toString()
    val outDir = layout.buildDirectory.dir("generated/cipherlogVersion")
    inputs.property("version", libraryVersion)
    outputs.dir(outDir)
    doLast {
        val file = outDir.get().file("com/rebels11/cipherlog/LibraryVersion.java").asFile
        file.parentFile.mkdirs()
        file.writeText(
            "package com.rebels11.cipherlog;\n\n" +
                "/** The library version, generated from gradle.properties. */\n" +
                "final class LibraryVersion {\n" +
                "    static final String VERSION = \"$libraryVersion\";\n\n" +
                "    private LibraryVersion() {\n    }\n}\n"
        )
    }
}
sourceSets.named("main") { java.srcDir(generateVersion) }

dependencies {
    // The only runtime dependency: HPKE and ChaCha20-Poly1305. tink-android is a plain jar that also runs on a JVM,
    // so one artifact serves both; an app that already has tink-android 1.24.0 gets a single copy.
    api(libs.tink.android) {
        // Tink's own dependencies that the classes cipherlog calls never load: gson (JSON keysets), and annotation-only
        // jars (androidx.annotation, which would bring kotlin-stdlib 1.7.10 into Java apps; jsr305; Error Prone). The
        // exclusions go into the published POM. The vectors and samples run without them, and the sample's minified
        // release builds without them. An app that uses those parts of Tink depends on Tink itself and gets them.
        exclude(group = "com.google.code.gson")
        exclude(group = "androidx.annotation")
        exclude(group = "com.google.code.findbugs")
        exclude(group = "com.google.errorprone")
    }
    // Compile only (not in the POM): javac reads the annotations on Tink's classes and warns, under -Werror, without them.
    compileOnly(libs.error.prone.annotations)

    testImplementation(libs.junit)

    // Build-time only: fails the build when main code uses a Java API that Android 6.0 (API 23) does not have.
    signature(libs.gummy.bears.api23) { artifact { type = "signature" } }
}

animalsniffer {
    sourceSets = listOf(project.sourceSets.getByName("main"))
}

val repoRoot = rootProject.layout.projectDirectory.dir("..")

tasks.test {
    useJUnit()
    // Fixed, so a reader that needs memory in proportion to hostile input (ArmorTest) fails here and not only on a phone.
    maxHeapSize = "512m"
    // The Android 6 API check runs with the tests, so the usual test command catches a Java API Android lacks.
    dependsOn(tasks.named("animalsnifferMain"))
    // vectors/ (records.json, test-key.json, samples/*) is read in place.
    systemProperty("cipherlog.repoRoot", repoRoot.asFile.absolutePath)
    inputs.dir(repoRoot.dir("vectors")).withPropertyName("vectors")
    environment("CIPHERLOG_WRITE_SAMPLES", System.getenv("CIPHERLOG_WRITE_SAMPLES") ?: "")
    testLogging {
        events("failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}

mavenPublishing {
    configure(JavaLibrary(javadocJar = JavadocJar.Javadoc(), sourcesJar = SourcesJar.Sources()))
    publishToMavenCentral(automaticRelease = true)
    // CI passes ORG_GRADLE_PROJECT_signingInMemoryKey; without a key (a local publishToMavenLocal) nothing is signed.
    if (!providers.gradleProperty("signingInMemoryKey").orNull.isNullOrBlank()) signAllPublications()
}
