package com.github.traderjoe95.mls.protocol.util

import java.time.temporal.ChronoUnit
import java.time.temporal.Temporal
import kotlin.time.Duration

inline operator fun <reified T : Temporal> T.plus(duration: Duration): T = plus(duration.inWholeNanoseconds, ChronoUnit.NANOS) as T

inline operator fun <reified T : Temporal> T.minus(duration: Duration): T = plus(duration.inWholeNanoseconds, ChronoUnit.NANOS) as T
