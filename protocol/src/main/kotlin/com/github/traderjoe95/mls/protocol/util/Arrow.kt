package com.github.traderjoe95.mls.protocol.util

import arrow.core.raise.Raise
import arrow.core.raise.recover

inline fun <E, T> unsafe(block: Raise<E>.() -> T): T =
  recover(
    block = block,
    recover = { throw RuntimeException("Error raised in unsafe { } block: $it") },
  )

inline fun <T, U> T.foldWith(
  items: Iterable<U>,
  block: T.(U) -> T,
): T = items.fold(this, block)
