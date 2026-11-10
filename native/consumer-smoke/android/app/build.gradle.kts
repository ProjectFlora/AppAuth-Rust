plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.projectflora.appauth.consumer"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.projectflora.appauth.consumer"
        minSdk = 34
        targetSdk = 35
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
}

dependencies {
    implementation(files("libs/appauth-rust.aar"))
    implementation("net.java.dev.jna:jna:5.12.0@aar")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    implementation("androidx.browser:browser:1.8.0")

    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
}
