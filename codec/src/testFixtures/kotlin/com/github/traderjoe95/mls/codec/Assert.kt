package com.github.traderjoe95.mls.codec

import arrow.core.raise.Raise
import arrow.core.raise.either
import com.github.traderjoe95.mls.codec.error.AnyError
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.matchers.types.shouldBeTypeOf

inline fun <T> shouldNotRaise(crossinline block: Raise<AnyError>.() -> T): T =
  either(block).shouldBeRight { "No error expected, but a $it was raised" }

inline fun <reified T : Any> shouldRaise(crossinline block: Raise<AnyError>.() -> Any?): T =
  either(block).shouldBeLeft().shouldBeTypeOf<T>()

inline fun shouldRaiseAny(crossinline block: Raise<AnyError>.() -> Any?): AnyError = either(block).shouldBeLeft()
