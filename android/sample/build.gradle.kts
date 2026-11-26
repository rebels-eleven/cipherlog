// :sample: a tiny Android app showing the three-line integration and the share button. It uses the TEST key from
// vectors/test-key.json and says so on screen; a real app ships its own public key. Not published.
plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "com.rebels11.cipherlog.sample"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.rebels11.cipherlog.sample"
        minSdk = 23
        targetSdk = 36
        versionCode = 1
        versionName = providers.gradleProperty("VERSION_NAME").get()
    }

    buildTypes {
        release {
            // R8 on, as in a production app: CI builds this variant so a missing consumer rule fails the build here.
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

dependencies {
    implementation(project(":cipherlog"))
}

// -Pcipherlog.sample.withoutTink=true builds the sample as an app that excluded Tink: the minified release must still
// build (the writer then turns itself off at run time, see Crypto.java).
if (providers.gradleProperty("cipherlog.sample.withoutTink").orNull == "true") {
    configurations.configureEach { exclude(group = "com.google.crypto.tink") }
}
