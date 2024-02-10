pluginManagement {
  repositories {
    mavenCentral()
    gradlePluginPortal()
  }

  val kotlinVersion: String by settings

  val ktlintVersion: String by settings
  val koverVersion: String by settings

  plugins {
    kotlin("jvm") version kotlinVersion

    id("org.jlleitschuh.gradle.ktlint") version ktlintVersion
    id("org.jlleitschuh.gradle.ktlint-idea") version ktlintVersion

    id("org.jetbrains.kotlinx.kover") version koverVersion
  }
}

plugins {
  id("org.gradle.toolchains.foojay-resolver-convention") version "0.5.0"
}

rootProject.name = "mls"
include("codec")
include("protocol")
include("ulid")
include("service:auth")
include("service:delivery")
include("playground")
