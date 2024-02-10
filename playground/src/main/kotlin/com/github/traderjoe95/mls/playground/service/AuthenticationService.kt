package com.github.traderjoe95.mls.playground.service

import arrow.core.Either
import arrow.core.raise.either
import arrow.core.right
import com.github.traderjoe95.mls.protocol.error.CredentialError
import com.github.traderjoe95.mls.protocol.error.CredentialIdentityValidationError
import com.github.traderjoe95.mls.protocol.error.CredentialValidationError
import com.github.traderjoe95.mls.protocol.error.IsSameClientError
import com.github.traderjoe95.mls.protocol.types.BasicCredential
import com.github.traderjoe95.mls.protocol.types.Credential
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode

object AuthenticationService : com.github.traderjoe95.mls.protocol.service.AuthenticationService<String> {
  override suspend fun authenticateCredentialIdentity(
    identity: String,
    leafNode: LeafNode<*>,
  ): Either<CredentialIdentityValidationError, Unit> =
    either {
      when (val cred = leafNode.credential) {
        is BasicCredential ->
          if (cred.identity.decodeToString() != identity) raise(CredentialIdentityValidationError.IdentityMismatch)

        else -> raise(CredentialError.UnsupportedCredential(cred.credentialType))
      }
    }

  override suspend fun authenticateCredential(leafNode: LeafNode<*>): Either<CredentialValidationError, String> =
    either {
      when (val cred = leafNode.credential) {
        is BasicCredential -> cred.identity.decodeToString()
        else -> raise(CredentialError.UnsupportedCredential(cred.credentialType))
      }
    }

  override suspend fun authenticateCredentials(leafNodes: List<LeafNode<*>>): List<Either<CredentialValidationError, String>> =
    leafNodes.map { authenticateCredential(it) }

  override suspend fun isSameClient(
    credentialA: Credential,
    credentialB: Credential,
  ): Either<IsSameClientError, Boolean> = (credentialA == credentialB).right()
}
