package com.github.traderjoe95.mls.protocol.testing

import arrow.core.raise.Raise
import arrow.core.raise.either
import com.github.traderjoe95.mls.protocol.types.RefinedBytes
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

infix fun <T : RefinedBytes<T>> T.shouldBeEq(other: T) = bytes shouldBe other.bytes

inline fun <reified E : Any> shouldRaise(block: Raise<E>.() -> Any): E = either(block).shouldBeLeft().shouldBeInstanceOf<E>()
