import kotlinx.kover.gradle.plugin.KoverGradlePlugin
import org.jlleitschuh.gradle.ktlint.KtlintPlugin

plugins {
  kotlin("jvm") apply false
  id("org.jlleitschuh.gradle.ktlint") apply false
  id("org.jetbrains.kotlinx.kover") apply false
}

allprojects {
  apply<KtlintPlugin>()

  repositories {
    mavenCentral()
  }
}

subprojects {
  apply<KoverGradlePlugin>()
}
