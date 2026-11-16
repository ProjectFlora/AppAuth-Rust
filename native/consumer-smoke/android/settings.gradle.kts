pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral {
            // Disable Gradle Module Metadata to force verification of the POM file
            metadataSources {
                mavenPom()
            }
            ignoreGradleMetadataRedirection()
        }
    }
}

rootProject.name = "appauth-rust-release-consumer"
include(":app")
