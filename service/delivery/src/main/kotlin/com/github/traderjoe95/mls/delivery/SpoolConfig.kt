package com.github.traderjoe95.mls.delivery

import java.nio.file.Path

data class SpoolConfig(
  val persistence: Boolean = true,
  val directory: Path = Path.of("./.spool"),
)
