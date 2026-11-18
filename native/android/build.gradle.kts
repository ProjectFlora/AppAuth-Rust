plugins {
    id("com.android.library") version "8.11.1"
    id("org.jetbrains.kotlin.android") version "2.2.20"
    id("com.vanniktech.maven.publish") version "0.34.0"
}

val repositoryRoot = rootDir.resolve("../..").canonicalFile
// Release runs pass -PreleaseVersion=X.Y.Z. The SNAPSHOT fallback is rejected by
// Maven Central, so a publish without an explicit version cannot succeed.
val releaseVersion = providers.gradleProperty("releaseVersion").getOrElse("0.0.0-SNAPSHOT")
val generatedBindings = layout.buildDirectory.dir("generated/uniffi")
val androidRustLibraries = layout.buildDirectory.dir("generated/rust/jniLibs")
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

val buildAndroidRustLibraries by tasks.registering(Exec::class) {
    workingDir(repositoryRoot)
    commandLine(
        "bash",
        repositoryRoot.resolve("scripts/check-android-targets.sh").absolutePath,
        androidRustLibraries.get().asFile.absolutePath,
    )
    inputs.files(
        repositoryRoot.resolve("Cargo.toml"),
        repositoryRoot.resolve("Cargo.lock"),
        repositoryRoot.resolve("scripts/check-android-targets.sh"),
        fileTree(repositoryRoot.resolve("src")),
    )
    outputs.dir(androidRustLibraries)
}

// License notices for the release AAR, in classes.jar under a path of their
// own so they do not collide with other libraries' META-INF/LICENSE in apps.
// Only release builds ship them, so debug builds do not need cargo-about.
val generatedLicenses = layout.buildDirectory.dir("generated/licenses")
val generateLicenseNotices by tasks.registering(Exec::class) {
    val noticeDir = generatedLicenses.map { it.dir("META-INF/native-oidc").asFile }
    workingDir(repositoryRoot)
    commandLine(
        "bash",
        repositoryRoot.resolve("scripts/generate-third-party-licenses.sh").absolutePath,
        noticeDir.get().resolve("THIRD_PARTY_LICENSES.txt").absolutePath,
    )
    inputs.files(
        repositoryRoot.resolve("Cargo.toml"),
        repositoryRoot.resolve("Cargo.lock"),
        repositoryRoot.resolve("LICENSE"),
        repositoryRoot.resolve("about.toml"),
        repositoryRoot.resolve("about.hbs"),
        repositoryRoot.resolve("scripts/generate-third-party-licenses.sh"),
    )
    outputs.dir(generatedLicenses)
    doLast {
        repositoryRoot.resolve("LICENSE").copyTo(noticeDir.get().resolve("LICENSE"), overwrite = true)
    }
}

android {
    namespace = "net.projectflora.nativeoidc"
    compileSdk = 35

    defaultConfig {
        minSdk = 28
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
    sourceSets.getByName("main").jniLibs.srcDir(androidRustLibraries)
    // The task (not its directory) as the source, so every task reading it depends on it.
    sourceSets.getByName("release").resources.srcDir(generateLicenseNotices)

    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

tasks.named("preBuild").configure {
    dependsOn(generateUniFfiBindings)
}

tasks.configureEach {
    if (name == "mergeDebugJniLibFolders" || name == "mergeReleaseJniLibFolders") {
        dependsOn(buildAndroidRustLibraries)
    }
    // The published sources and javadoc jars read the generated bindings.
    if (name == "sourceReleaseJar" || name.startsWith("javaDocRelease")) {
        dependsOn(generateUniFfiBindings)
    }
}

dependencies {
    api("net.java.dev.jna:jna:5.12.0@aar")
    api("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    implementation("androidx.browser:browser:1.8.0")

    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.uiautomator:uiautomator:2.3.0")

    testImplementation("junit:junit:4.13.2")
}

mavenPublishing {
    coordinates("net.project-flora.nativeoidc", "native-oidc-android", releaseVersion)
    publishToMavenCentral()
    // The release workflow supplies the key as ORG_GRADLE_PROJECT_signingInMemoryKey.
    // Without it (local builds, CI checks) publications are left unsigned;
    // Maven Central rejects unsigned uploads.
    if (providers.gradleProperty("signingInMemoryKey").isPresent) {
        signAllPublications()
    }

    pom {
        name.set("NativeOIDC Android")
        description.set("Android adapter and UniFFI Kotlin bindings for NativeOIDC, a Rust OAuth 2.0 and OpenID Connect client for native apps. NativeOIDC is an independent project by ProjectFlora. It is not affiliated with, endorsed by, or sponsored by the OpenID Foundation or the AppAuth projects (AppAuth-iOS, AppAuth-Android). OpenID is a trademark of the OpenID Foundation.")
        url.set("https://github.com/ProjectFlora/NativeOIDC")
        licenses {
            license {
                name.set("The Apache License, Version 2.0")
                url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                distribution.set("repo")
            }
        }
        developers {
            developer {
                id.set("projectflora")
                name.set("ProjectFlora")
                url.set("https://github.com/ProjectFlora")
            }
        }
        scm {
            url.set("https://github.com/ProjectFlora/NativeOIDC")
            connection.set("scm:git:https://github.com/ProjectFlora/NativeOIDC.git")
            developerConnection.set("scm:git:ssh://git@github.com/ProjectFlora/NativeOIDC.git")
        }
    }
}
