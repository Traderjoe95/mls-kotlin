package com.github.traderjoe95.mls.codec.error

sealed interface DecoderError : AnyError {
  data class PrematureEndOfStream(val position: UInt, val expectedBytes: UInt, val remaining: UInt) : DecoderError

  data class InvalidLengthEncoding(val position: UInt) : DecoderError

  data class BadLength(
    val position: UInt,
    val length: UInt,
    val expectedInterval: UIntRange,
    val expectedMultipleOf: UInt,
  ) : DecoderError

  data class UnknownEnumValue(val position: UInt, val enum: String, val ord: UInt) : DecoderError

  data class ExtraDataInStream(val position: UInt, val extraBytes: UInt) : DecoderError

  data class InvalidEnumValue(val position: UInt, val enum: String, val name: String) : DecoderError

  data class InvalidFieldValue(
    val position: UInt,
    val struct: String,
    val fieldIdx: UInt,
    val expected: Any?,
    val actual: Any?,
  ) : DecoderError

  data class UnexpectedError(val message: String) : DecoderError
}
