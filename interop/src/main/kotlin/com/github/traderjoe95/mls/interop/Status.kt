package com.github.traderjoe95.mls.interop

import io.grpc.Status
import io.grpc.StatusException

fun invalidArgument(message: String): Nothing = throw StatusException(Status.INVALID_ARGUMENT.withDescription(message))
