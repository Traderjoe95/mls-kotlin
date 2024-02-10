package com.github.traderjoe95.mls.codec.error

sealed interface EncoderError : AnyError {
  data object BadLength : EncoderError

  data class InvalidEnumValue(val enum: String, val name: String) : EncoderError

  data class InvalidFieldValue(val struct: String, val fieldIdx: UInt, val expected: Any?, val actual: Any?) :
    EncoderError

  data class WrongVariant(val struct: String, val fieldIdx: UInt, val expected: String, val value: Any?) : EncoderError
}
