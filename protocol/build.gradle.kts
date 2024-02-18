plugins {
  kotlin("jvm")

  `java-library`
//  `java-test-fixtures`
}

val projectVersion: String by project

group = "com.github.traderjoe95.mls"
version = projectVersion

repositories {
  mavenCentral()
}

// Language Stack Dependency Versions
val coroutinesVersion: String by project

// Dependency Versions
val arrowVersion: String by project

val bouncycastleVersion: String by project

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

  // Codec
  implementation(project(":codec"))

  // ULID
  implementation(project(":ulid"))

  // Crypto
  implementation("org.bouncycastle:bcprov-jdk18on:$bouncycastleVersion")
  implementation("org.bouncycastle:bcpkix-jdk18on:$bouncycastleVersion")

  testImplementation(kotlin("test"))

  // Test Dependencies
  testImplementation(kotlin("test"))

  testImplementation(platform("io.kotest:kotest-bom:$kotestVersion"))
  testImplementation("io.kotest:kotest-runner-junit5")
  testImplementation("io.kotest:kotest-assertions-core")
  testImplementation("io.kotest:kotest-property")
  testImplementation("io.kotest.extensions:kotest-assertions-arrow:$kotestArrowVersion")

  testImplementation("io.mockk:mockk:$mockkVersion")

  testImplementation(testFixtures(project(":codec")))

//  testFixturesApi(platform("io.kotest:kotest-bom:$kotestVersion"))
//  testFixturesImplementation("io.kotest:kotest-assertions-core")
//  testFixturesApi("io.kotest:kotest-property")
//  testFixturesImplementation("io.kotest.extensions:kotest-assertions-arrow:$kotestArrowVersion")
}

tasks.test {
  useJUnitPlatform()
  finalizedBy(tasks.koverHtmlReport, tasks.koverXmlReport, tasks.koverBinaryReport)
}

kotlin {
  jvmToolchain(21)

  compilerOptions {
    allWarningsAsErrors.set(true)
    freeCompilerArgs.addAll("-Xcontext-receivers", "-X")
  }
}

ktlint {
  version.set("1.1.1")
}
