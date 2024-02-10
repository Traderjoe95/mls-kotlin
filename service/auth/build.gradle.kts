plugins {
  kotlin("jvm")

  application
}

val projectVersion: String by project

group = "com.github.traderjoe95.mls.service"
version = projectVersion

repositories {
  mavenCentral()
}

// Language Stack Dependency Versions
val coroutinesVersion: String by project

// Dependency Versions
val arrowVersion: String by project

val bouncycastleVersion: String by project

val vertxVersion: String by project

// Test Dependency Versions
val kotestVersion: String by project
val kotestArrowVersion: String by project
val mockkVersion: String by project

dependencies {
  // Kotlin Standard Library
  implementation(kotlin("stdlib-jdk8"))
  implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:$coroutinesVersion")

  // Vert.x Stack
  implementation(platform("io.vertx:vertx-stack-depchain:$vertxVersion"))
  implementation("io.vertx:vertx-lang-kotlin")
  implementation("io.vertx:vertx-lang-kotlin-coroutines")
  implementation("io.vertx:vertx-web")

  // Arrow
  api(platform("io.arrow-kt:arrow-stack:$arrowVersion"))
  api("io.arrow-kt:arrow-core")

  // Codec
  implementation(project(":codec"))
  implementation(project(":protocol"))

  // ULID
  implementation(project(":ulid"))

  // Crypto
  implementation("org.bouncycastle:bcprov-jdk18on:$bouncycastleVersion")
  implementation("org.bouncycastle:bcpkix-jdk18on:$bouncycastleVersion")

  // Test Dependencies
  testImplementation(kotlin("test"))

  testImplementation(platform("io.kotest:kotest-bom:$kotestVersion"))
  testImplementation("io.kotest:kotest-runner-junit5")
  testImplementation("io.kotest:kotest-assertions-core")
  testImplementation("io.kotest:kotest-property")
  testImplementation("io.kotest.extensions:kotest-assertions-arrow:$kotestArrowVersion")

  testImplementation("io.mockk:mockk:$mockkVersion")
}

tasks.test {
  useJUnitPlatform()
  finalizedBy(tasks.koverHtmlReport, tasks.koverXmlReport, tasks.koverBinaryReport)
}

kotlin {
  jvmToolchain(21)

  compilerOptions {
    allWarningsAsErrors.set(true)
    freeCompilerArgs.add("-Xcontext-receivers")
  }
}

ktlint {
  version.set("1.1.1")
}
