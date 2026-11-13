buildscript {
    dependencies {
        // AGP 9 bundles KGP 2.2.10; pin the current Kotlin instead. AGP
        // upgrades lower versions automatically, so this only raises it.
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:2.4.21")
    }
}

plugins {
    // AGP 9 has built-in Kotlin support; the separate kotlin-android plugin
    // must not be applied (https://kotl.in/gradle/agp-built-in-kotlin).
    id("com.android.application") version "9.5.1" apply false
}
