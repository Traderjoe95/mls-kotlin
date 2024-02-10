package com.github.traderjoe95.mls.protocol.error

import com.github.traderjoe95.mls.protocol.types.CredentialType

sealed interface IsSameClientError : CommitError, JoinError, ResumptionJoinError

sealed interface CredentialValidationError : LeafNodeCheckError, ResumptionError, CredentialIdentityValidationError {
  data object InvalidCredential : CredentialValidationError
}

sealed interface CredentialIdentityValidationError {
  data object IdentityMismatch : CredentialIdentityValidationError
}

sealed interface CredentialError : CredentialValidationError, IsSameClientError {
  data class BadCredentialFormat(val reason: String) : CredentialError

  data class UnsupportedCredential(val type: CredentialType) : CredentialError
}

sealed interface AuthenticationServiceError : CredentialError
