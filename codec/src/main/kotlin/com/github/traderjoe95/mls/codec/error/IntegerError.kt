package com.github.traderjoe95.mls.codec.error

sealed class IntegerError : EncoderError, DecoderError {
  data class ValueTooBig(val type: String, val value: UInt) : IntegerError()
}
