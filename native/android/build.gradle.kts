plugins {
    id("com.android.library") version "8.11.1"
    id("org.jetbrains.kotlin.android") version "2.2.20"
    id("maven-publish")
    id("signing")
}

val releaseVersion = providers.gradleProperty("releaseVersion").orNull ?: "0.5.1"

val repositoryRoot = rootDir.resolve("../..").canonicalFile
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

android {
    namespace = "net.projectflora.appauth"
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

afterEvaluate {
    signing {
        useGpgCmd()
        sign(publishing.publications["release"])
    }
    
    publishing {
        publications {
            create<MavenPublication>("release") {
                groupId = "net.project-flora"
                artifactId = "appauth-rust-android"
                version = releaseVersion

                from(components["release"])
                
                pom {
                    name.set("AppAuth-Rust Android")
                    description.set("Rust-based AppAuth library for Android")
                    url.set("https://github.com/ProjectFlora/AppAuth-Rust")
                    licenses { 
                        license { 
                            name.set("Apache License 2.0")
                            url.set("https://www.apache.org/licenses/LICENSE-2.0")
                            distribution.set("repo" as String)
                        }
                    }
                    developers { 
                        developer { 
                            id.set("projectflora") 
                            name.set("ProjectFlora")
                            email.set("oss@projectflora.net")
                        }
                    }
                    scm { 
                        url.set("https://github.com/ProjectFlora/AppAuth-Rust")
                        connection.set("scm:git:https://github.com/ProjectFlora/AppAuth-Rust.git")
                    }
                }
            }
        }
    }
}
