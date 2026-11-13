plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.lidessen.keyref.source"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.lidessen.keyref.source"
        minSdk = 26
        targetSdk = 35
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
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    // RFC 9180 HPKE + X25519/Ed25519 (design §9.2: must match proto/crypto
    // byte-for-byte; the cross-language golden vectors are the gate).
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    // QR rendering of the pairing payload (protocol §9.1).
    implementation("com.google.zxing:core:3.5.3")
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.work:work-runtime-ktx:2.9.1")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
}
