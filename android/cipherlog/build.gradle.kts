// :cipherlog: the Android library (AAR). A static facade that mirrors android.util.Log, Logcat passthrough, default
// directory, process detection, device collectors and a mail share intent through the library's own provider. Plain
// Java; the only dependency is :cipherlog-core (which brings Tink).
import com.vanniktech.maven.publish.AndroidSingleVariantLibrary
import com.vanniktech.maven.publish.JavadocJar
import com.vanniktech.maven.publish.SourcesJar

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.maven.publish)
}

group = providers.gradleProperty("GROUP").get()
version = providers.gradleProperty("VERSION_NAME").get()

android {
    namespace = "com.rebels11.cipherlog.android"
    compileSdk = 36

    defaultConfig {
        minSdk = 23
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    lint {
        abortOnError = true
        warningsAsErrors = false
    }

    testOptions {
        // android.jar stubs return defaults instead of throwing, so the pure parts can be unit-tested on the JVM.
        unitTests.isReturnDefaultValues = true
    }
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.compilerArgs.addAll(listOf("-Xlint:all,-serial,-options,-classfile", "-Werror"))
}

dependencies {
    api(project(":cipherlog-core"))
    testImplementation(libs.junit)
}

val repoRoot = rootProject.layout.projectDirectory.dir("..")
tasks.withType<Test>().configureEach {
    systemProperty("cipherlog.repoRoot", repoRoot.asFile.absolutePath)
}

mavenPublishing {
    configure(
        AndroidSingleVariantLibrary(
            javadocJar = JavadocJar.Javadoc(),
            sourcesJar = SourcesJar.Sources(),
            variant = "release",
        ),
    )
    publishToMavenCentral(automaticRelease = true)
    // CI passes ORG_GRADLE_PROJECT_signingInMemoryKey; without a key (a local publishToMavenLocal) nothing is signed.
    if (!providers.gradleProperty("signingInMemoryKey").orNull.isNullOrBlank()) signAllPublications()
}
