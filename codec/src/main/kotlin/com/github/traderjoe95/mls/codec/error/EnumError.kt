package com.github.traderjoe95.mls.codec.error

interface EnumError : AnyError {
  data class AmbiguousOrd(val enum: String, val overlap: Map<String, Set<String>>) : EnumError

  data class UndefinedOrd(val enum: String, val undefined: Set<String>) : EnumError

  data class NoValues(val enum: String) : EnumError
}
