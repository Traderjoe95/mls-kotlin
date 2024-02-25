package com.github.traderjoe95.mls.demo.util

import java.time.temporal.Temporal
import kotlin.time.Duration
import kotlin.time.toJavaDuration

@Suppress("UNCHECKED_CAST")
operator fun <T : Temporal> T.plus(duration: Duration): T = (this + duration.toJavaDuration()) as T

@Suppress("UNCHECKED_CAST")
operator fun <T : Temporal> T.minus(duration: Duration): T = (this - duration.toJavaDuration()) as T
