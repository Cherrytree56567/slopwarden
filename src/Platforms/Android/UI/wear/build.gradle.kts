plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

/*
 * Wear OS app. It is a standalone vault (its own applicationId, its own copy of the vault
 * files) that talks to the same native core as the phone app: libclientwarden.so is built
 * once by CMake into the phone app's jniLibs and reused here, and the JNI class names
 * (com.ct5.clientwarden.Native / SecretVault) are part of that ABI, so those two files are
 * kept in that package even though the rest of the UI lives in com.ct5.clientwarden.wear.
 */
android {
    namespace = "com.ct5.clientwarden.wear"
    compileSdk {
        version = release(37)
    }

    defaultConfig {
        applicationId = "com.ct5.clientwarden.wear"
        minSdk = 31
        targetSdk = 37
        versionCode = 1
        versionName = "1.0"

        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    sourceSets {
        getByName("main") {
            // Built by cmake/android.cmake into the phone app's jniLibs; shared, not copied.
            jniLibs.srcDirs("../app/src/main/jniLibs")
            // The passphrase word list the core needs, also shared.
            assets.srcDirs("../app/src/main/assets")
        }
    }

    packaging {
        jniLibs {
            useLegacyPackaging = false
        }
    }

    buildTypes {
        release {
            optimization {
                enable = false
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    buildFeatures {
        compose = true
    }
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.compose.foundation)
    implementation(libs.androidx.compose.foundation.layout)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.wear.compose.foundation)
    implementation(libs.kotlinx.coroutines.android)
}
