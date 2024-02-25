plugins {
  kotlin("jvm")
  `java-test-fixtures`
}

group = "com.github.traderjoe95.mls"

repositories {
  mavenCentral()
}

val coroutinesVersion: String by project

val vertxVersion: String by project

val kotestVersion: String by project

dependencies {
  implementation(kotlin("stdlib-jdk8"))
  implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:$coroutinesVersion")

  api(platform("io.vertx:vertx-stack-depchain:$vertxVersion"))
  api("io.vertx:vertx-core")
  implementation("io.vertx:vertx-lang-kotlin")
  implementation("io.vertx:vertx-lang-kotlin-coroutines")

  api(project(":protocol"))

  testImplementation(kotlin("test"))

  testFixturesApi(platform("io.kotest:kotest-bom:$kotestVersion"))
  testFixturesImplementation("io.kotest:kotest-assertions-core")
  testFixturesApi("io.kotest:kotest-property")
}

tasks.test {
  useJUnitPlatform()
}

kotlin {
  jvmToolchain(21)

  compilerOptions {
    freeCompilerArgs.addAll("-Xcontext-receivers")

    allWarningsAsErrors.set(true)
  }
}
