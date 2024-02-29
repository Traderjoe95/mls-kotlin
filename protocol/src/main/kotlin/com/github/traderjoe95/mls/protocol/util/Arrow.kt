package com.github.traderjoe95.mls.protocol.util

import arrow.core.raise.Raise
import arrow.core.raise.nullable
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

fun <A : Any, B : Any> Pair<A?, B?>.hoistNulls(): Pair<A, B>? = nullable { first.bind() to second.bind() }

fun <A : Any, B : Any> Iterable<Pair<A?, B?>>.filterInternalNulls(): Iterable<Pair<A, B>> = mapNotNull { it.hoistNulls() }

inline fun <T, A : Any, B : Any> Iterable<T>.mapNoInternalNulls(transform: (T) -> Pair<A?, B?>): Iterable<Pair<A, B>> =
  mapNotNull { transform(it).hoistNulls() }
