package com.github.traderjoe95.mls.protocol.util

inline fun <T, U> T.foldWith(
  items: Iterable<U>,
  block: T.(U) -> T,
): T = items.fold(this, block)
