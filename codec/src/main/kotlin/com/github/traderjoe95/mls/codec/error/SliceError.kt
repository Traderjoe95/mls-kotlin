package com.github.traderjoe95.mls.codec.error

sealed interface SliceError : AnyError {
  data class IndexOutOfBounds(val length: UInt, val index: UInt) : SliceError
}
