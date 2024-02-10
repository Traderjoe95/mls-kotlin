plugins {
  kotlin("jvm")

  `java-library`
  `java-test-fixtures`
}

group = "de.traderjoe"
version = "1.0.0-SNAPSHOT"

repositories {
  mavenCentral()
}

// Language Stack Dependency Versions
val coroutinesVersion: String by project

// Dependency Versions
val arrowVersion: String by project

// Test Dependency Versions
val kotestVersion: String by project
val kotestArrowVersion: String by project
val mockkVersion: String by project

dependencies {
  // Kotlin Standard Library
  implementation(kotlin("stdlib-jdk8"))
  implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:$coroutinesVersion")

  // Arrow
  api(platform("io.arrow-kt:arrow-stack:$arrowVersion"))
  api("io.arrow-kt:arrow-core")

  testImplementation(kotlin("test"))

  // Test Dependencies
  testImplementation(kotlin("test"))

  testImplementation(platform("io.kotest:kotest-bom:$kotestVersion"))
  testImplementation("io.kotest:kotest-runner-junit5")
  testImplementation("io.kotest:kotest-assertions-core")
  testImplementation("io.kotest:kotest-property")
  testImplementation("io.kotest.extensions:kotest-assertions-arrow:$kotestArrowVersion")

  testImplementation("io.mockk:mockk:$mockkVersion")

  testFixturesApi(platform("io.kotest:kotest-bom:$kotestVersion"))
  testFixturesImplementation("io.kotest:kotest-assertions-core")
  testFixturesApi("io.kotest:kotest-property")
  testFixturesImplementation("io.kotest.extensions:kotest-assertions-arrow:$kotestArrowVersion")
}

kotlin {
  jvmToolchain(21)

  compilerOptions {
    allWarningsAsErrors.set(true)
    freeCompilerArgs.addAll("-Xcontext-receivers")
  }

  target {
    compilations.getByName("testFixtures")
      .associateWith(compilations.getByName("main"))
  }
}

tasks.test {
  useJUnitPlatform()
  finalizedBy(tasks.koverHtmlReport, tasks.koverXmlReport, tasks.koverBinaryReport)
}

kover {
  excludeSourceSets {
    names("testFixtures")
  }
}

ktlint {
  version.set("1.1.1")
}
