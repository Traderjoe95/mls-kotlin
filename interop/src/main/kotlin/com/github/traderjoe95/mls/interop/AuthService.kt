package com.github.traderjoe95.mls.interop

import arrow.core.Either
import arrow.core.right
import com.github.traderjoe95.mls.protocol.error.CredentialIdentityValidationError
import com.github.traderjoe95.mls.protocol.error.CredentialValidationError
import com.github.traderjoe95.mls.protocol.error.IsSameClientError
import com.github.traderjoe95.mls.protocol.service.AuthenticationService
import com.github.traderjoe95.mls.protocol.types.BasicCredential
import com.github.traderjoe95.mls.protocol.types.Credential
import com.github.traderjoe95.mls.protocol.types.crypto.SignaturePublicKey

object AuthService : AuthenticationService<ByteArray> {
  override suspend fun authenticateCredentialIdentity(
    identity: ByteArray,
    signaturePublicKey: SignaturePublicKey,
    credential: Credential,
  ): Either<CredentialIdentityValidationError, Unit> = Unit.right()

  override suspend fun authenticateCredential(
    signaturePublicKey: SignaturePublicKey,
    credential: Credential,
  ): Either<CredentialValidationError, ByteArray> = (credential as BasicCredential).identity.right()

  override suspend fun authenticateCredentials(
    credentials: Iterable<Pair<SignaturePublicKey, Credential>>,
  ): List<Either<CredentialValidationError, ByteArray>> = credentials.map { (key, cred) -> authenticateCredential(key, cred) }

  override suspend fun isSameClient(
    credentialA: Credential,
    credentialB: Credential,
  ): Either<IsSameClientError, Boolean> = (credentialA == credentialB).right()
}
