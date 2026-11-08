plugins {
    id("com.android.library") version "8.11.1"
    id("org.jetbrains.kotlin.android") version "2.2.20"
}

val repositoryRoot = rootDir.resolve("../..").canonicalFile
val generatedBindings = layout.buildDirectory.dir("generated/uniffi")
val generateUniFfiBindings by tasks.registering(Exec::class) {
    workingDir(repositoryRoot)
    commandLine(
        "bash",
        repositoryRoot.resolve("scripts/generate-bindings.sh").absolutePath,
        generatedBindings.get().asFile.absolutePath,
    )
    inputs.files(
        repositoryRoot.resolve("Cargo.toml"),
        repositoryRoot.resolve("Cargo.lock"),
        repositoryRoot.resolve("scripts/generate-bindings.sh"),
        fileTree(repositoryRoot.resolve("src")),
    )
    outputs.dir(generatedBindings)
}

android {
    namespace = "com.projectflora.appauth"
    compileSdk = 35

    defaultConfig {
        minSdk = 34
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    sourceSets.getByName("main").java.srcDir(generatedBindings.map { it.dir("kotlin") })

    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

tasks.named("preBuild").configure {
    dependsOn(generateUniFfiBindings)
}

dependencies {
    api("net.java.dev.jna:jna:5.12.0@aar")
    api("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    implementation("androidx.browser:browser:1.8.0")

    testImplementation("junit:junit:4.13.2")
}
