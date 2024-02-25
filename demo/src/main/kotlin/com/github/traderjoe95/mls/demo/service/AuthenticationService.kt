package com.github.traderjoe95.mls.demo.service

import arrow.core.Either
import arrow.core.raise.either
import arrow.core.right
import com.github.traderjoe95.mls.protocol.error.CredentialError
import com.github.traderjoe95.mls.protocol.error.CredentialIdentityValidationError
import com.github.traderjoe95.mls.protocol.error.CredentialValidationError
import com.github.traderjoe95.mls.protocol.error.IsSameClientError
import com.github.traderjoe95.mls.protocol.types.BasicCredential
import com.github.traderjoe95.mls.protocol.types.Credential
import com.github.traderjoe95.mls.protocol.types.crypto.SignaturePublicKey

object AuthenticationService : com.github.traderjoe95.mls.protocol.service.AuthenticationService<String> {
  override suspend fun authenticateCredentialIdentity(
    identity: String,
    signaturePublicKey: SignaturePublicKey,
    credential: Credential,
  ): Either<CredentialIdentityValidationError, Unit> =
    either {
      when (credential) {
        is BasicCredential ->
          if (credential.identity.decodeToString() != identity) {
            raise(CredentialIdentityValidationError.IdentityMismatch)
          }

        else -> raise(CredentialError.UnsupportedCredential(credential.credentialType))
      }
    }

  override suspend fun authenticateCredential(
    signaturePublicKey: SignaturePublicKey,
    credential: Credential,
  ): Either<CredentialValidationError, String> =
    either {
      when (credential) {
        is BasicCredential -> credential.identity.decodeToString()
        else -> raise(CredentialError.UnsupportedCredential(credential.credentialType))
      }
    }

  override suspend fun authenticateCredentials(
    credentials: Iterable<Pair<SignaturePublicKey, Credential>>,
  ): List<Either<CredentialValidationError, String>> = credentials.map { (key, credential) -> authenticateCredential(key, credential) }

  override suspend fun isSameClient(
    credentialA: Credential,
    credentialB: Credential,
  ): Either<IsSameClientError, Boolean> = (credentialA == credentialB).right()
}
