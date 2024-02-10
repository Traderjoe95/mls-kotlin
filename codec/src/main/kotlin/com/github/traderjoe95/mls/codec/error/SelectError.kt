package com.github.traderjoe95.mls.codec.error

sealed class SelectError : AnyError {
  data class UnknownField(val struct: String, val field: String) : SelectError()

  data class ExpectedStruct(val struct: String, val field: String, val actualType: String) : SelectError()

  data class ExpectedEnum(val struct: String, val field: String, val expectedType: String, val actual: String) :
    SelectError()

  data class UnhandledSelectBranches(val struct: String, val enumType: String, val branch: Set<String>) : SelectError()
}
