package com.github.traderjoe95.mls.protocol.service

import arrow.core.Either
import com.github.traderjoe95.mls.protocol.error.CredentialIdentityValidationError
import com.github.traderjoe95.mls.protocol.error.CredentialValidationError
import com.github.traderjoe95.mls.protocol.error.IsSameClientError
import com.github.traderjoe95.mls.protocol.types.Credential
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode

interface AuthenticationService<Identity : Any> {
  suspend fun authenticateCredentialIdentity(
    identity: Identity,
    leafNode: LeafNode<*>,
  ): Either<CredentialIdentityValidationError, Unit>

  suspend fun authenticateCredential(leafNode: LeafNode<*>): Either<CredentialValidationError, Identity>

  suspend fun authenticateCredentials(vararg leafNodes: LeafNode<*>): List<Either<CredentialValidationError, Identity>> =
    authenticateCredentials(leafNodes.asList())

  suspend fun authenticateCredentials(leafNodes: List<LeafNode<*>>): List<Either<CredentialValidationError, Identity>>

  suspend fun isSameClient(
    credentialA: Credential,
    credentialB: Credential,
  ): Either<IsSameClientError, Boolean>
}
