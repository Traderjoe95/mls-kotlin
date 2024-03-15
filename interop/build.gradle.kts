import com.google.cloud.tools.jib.api.buildplan.ImageFormat
import com.google.protobuf.gradle.id

plugins {
  kotlin("jvm")
  id("com.google.protobuf") version "0.9.4"

  id("com.google.cloud.tools.jib") version "3.4.1"
}

val projectVersion: String by project

group = "com.github.traderjoe95.mls"
version = projectVersion

repositories {
  mavenCentral()
}

val coroutinesVersion: String by project

val vertxVersion: String by project
val grpcVersion = "1.62.2"
val grpcJavaVersion = "1.62.2"
val grpcKotlinVersion = "1.4.1"
val protobufVersion = "3.25.3"

val kotestVersion: String by project

dependencies {
  implementation(kotlin("stdlib-jdk8"))
  implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:$coroutinesVersion")

  implementation(platform("io.vertx:vertx-stack-depchain:$vertxVersion"))
  implementation("io.vertx:vertx-core")
  implementation("io.vertx:vertx-lang-kotlin")
  implementation("io.vertx:vertx-lang-kotlin-coroutines")
  implementation("io.vertx:vertx-grpc-server")
  implementation("io.vertx:vertx-grpc-client")

  implementation("io.grpc:grpc-kotlin-stub:$grpcKotlinVersion")
  implementation("io.grpc:grpc-protobuf:$grpcVersion")
  implementation("com.google.protobuf:protobuf-kotlin:$protobufVersion")

  implementation(project(":protocol"))

  testImplementation(kotlin("test"))
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

protobuf {
  protoc {
    artifact = "com.google.protobuf:protoc:$protobufVersion"
  }

  plugins {
    id("grpc") {
      artifact = "io.grpc:protoc-gen-grpc-java:$grpcJavaVersion"
    }

    id("grpckt") {
      artifact = "io.grpc:protoc-gen-grpc-kotlin:$grpcKotlinVersion:jdk8@jar"
    }

    id("vertx") {
      artifact = "io.vertx:vertx-grpc-protoc-plugin2:$vertxVersion"
    }
  }

  generateProtoTasks {
    ofSourceSet("main").forEach {
      it.plugins {
        // Apply the "grpc" plugin whose spec is defined above, without
        // options. Note the braces cannot be omitted, otherwise the
        // plugin will not be added. This is because of the implicit way
        // NamedDomainObjectContainer binds the methods.
        id("grpc") { }
        id("grpckt")
        id("vertx") { }
      }

      it.builtins {
        create("kotlin")
      }
    }
  }
}

jib {
  from {
    image = "eclipse-temurin:21-jre-alpine"
  }

  to {
    image = "ghcr.io/traderjoe95/mls-client/test-harness:${project.version}"
  }

  container {
    jvmFlags =
      listOf(
        "-Djava.security.egd=file:/dev/./urandom",
        "-Dvertx.disableDnsResolver=true",
        "-Dfile.encoding=UTF-8",
      )

    mainClass = "io.vertx.core.Launcher"
    args =
      listOf(
        "run",
        "com.github.traderjoe95.mls.interop.server.MlsClientVerticle",
      )

    ports = listOf("8080")

    labels.set(
      mapOf("version" to project.version.toString()),
    )

    format = ImageFormat.OCI
  }
}
