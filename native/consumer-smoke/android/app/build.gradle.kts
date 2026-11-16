plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "net.projectflora.appauth.consumer"
    compileSdk = 35

    defaultConfig {
        applicationId = "net.projectflora.appauth.consumer"
        minSdk = 28
        targetSdk = 35
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
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
    val appauthVersion: String? = project.findProperty("appauthVersion") as String?

    if (appauthVersion != null) {
        implementation("net.project-flora.appauth:appauth-rust-android:$appauthVersion")
    } else {
        implementation(files("libs/appauth-rust.aar"))
        implementation("net.java.dev.jna:jna:5.12.0@aar")
        implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
        implementation("androidx.browser:browser:1.8.0")
    }

    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
}
