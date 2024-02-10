package com.github.traderjoe95.mls.codec.error

import arrow.core.continuations.CancellationExceptionNoTrace

interface AnyError {
  class Exception(val error: AnyError) : CancellationExceptionNoTrace() {
    override val message: String
      get() = error.toString()
  }
}
