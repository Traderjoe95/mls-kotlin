package com.github.traderjoe95.mls.codec.error

sealed interface LengthError : AnyError {
  data class UndefinedLength(val lengthType: String, val dataType: String) : LengthError

  data class BadRange(val range: UIntRange) : LengthError

  data class BadLength(
    val length: UInt,
    val dataType: String,
    val dataTypeWidth: UInt,
  ) : LengthError
}
