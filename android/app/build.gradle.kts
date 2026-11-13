plugins {
    id("com.android.application")
}

android {
    namespace = "com.lidessen.keyref.source"
    compileSdk = 37

    defaultConfig {
        applicationId = "com.lidessen.keyref.source"
        minSdk = 26
        targetSdk = 37
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    // RFC 9180 HPKE + X25519/Ed25519 (design §9.2: must match proto/crypto
    // byte-for-byte; the cross-language golden vectors are the gate).
    implementation("org.bouncycastle:bcprov-jdk18on:1.87")
    // QR rendering of the pairing payload (protocol §9.1).
    implementation("com.google.zxing:core:3.5.4")
    implementation("androidx.core:core-ktx:1.19.1")
    implementation("androidx.appcompat:appcompat:1.8.0")
    implementation("androidx.work:work-runtime-ktx:2.12.0")
    implementation("com.squareup.okhttp3:okhttp:5.5.1")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20260814")
}
