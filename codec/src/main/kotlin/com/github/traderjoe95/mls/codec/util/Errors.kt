package com.github.traderjoe95.mls.codec.util

import arrow.core.getOrElse
import arrow.core.raise.Raise
import arrow.core.raise.either
import com.github.traderjoe95.mls.codec.error.AnyError

inline fun <T> throwAnyError(block: Raise<AnyError>.() -> T): T = either(block).getOrElse { throw AnyError.Exception(it) }
