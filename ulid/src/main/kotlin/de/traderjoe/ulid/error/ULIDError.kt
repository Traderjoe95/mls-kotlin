package de.traderjoe.ulid.error

sealed interface ULIDError {
  data class BadLength(val length: UInt, val expected: UInt) : ULIDError

  data class InvalidCharacter(val ch: Char) : ULIDError

  data object Overflow : ULIDError
}
