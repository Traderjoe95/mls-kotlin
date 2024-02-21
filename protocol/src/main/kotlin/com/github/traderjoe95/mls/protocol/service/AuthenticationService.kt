package com.github.traderjoe95.mls.protocol.service

import arrow.core.Either
import com.github.traderjoe95.mls.protocol.error.CredentialIdentityValidationError
import com.github.traderjoe95.mls.protocol.error.CredentialValidationError
import com.github.traderjoe95.mls.protocol.error.IsSameClientError
import com.github.traderjoe95.mls.protocol.types.Credential
import com.github.traderjoe95.mls.protocol.types.crypto.VerificationKey
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode

interface AuthenticationService<Identity : Any> {
  suspend fun authenticateCredentialIdentity(
    identity: Identity,
    verificationKey: VerificationKey,
    credential: Credential,
  ): Either<CredentialIdentityValidationError, Unit>

  suspend fun authenticateCredential(
    verificationKey: VerificationKey,
    credential: Credential,
  ): Either<CredentialValidationError, Identity>

  suspend fun authenticateCredentials(
    vararg credentials: Pair<VerificationKey, Credential>,
  ): List<Either<CredentialValidationError, Identity>> = authenticateCredentials(credentials.asList())

  suspend fun authenticateCredentials(
    credentials: Iterable<Pair<VerificationKey, Credential>>,
  ): List<Either<CredentialValidationError, Identity>>

  suspend fun isSameClient(
    credentialA: Credential,
    credentialB: Credential,
  ): Either<IsSameClientError, Boolean>
}

suspend fun <Identity : Any> AuthenticationService<Identity>.authenticateCredential(
  leafNode: LeafNode<*>,
): Either<CredentialValidationError, Identity> = authenticateCredential(leafNode.verificationKey, leafNode.credential)

suspend fun <Identity : Any> AuthenticationService<Identity>.authenticateCredentials(
  leafNodes: Iterable<LeafNode<*>>,
): List<Either<CredentialValidationError, Identity>> = authenticateCredentials(leafNodes.map { it.verificationKey to it.credential })
