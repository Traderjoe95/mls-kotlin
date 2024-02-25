package com.github.traderjoe95.mls.protocol.service

import arrow.core.Either
import com.github.traderjoe95.mls.protocol.error.CredentialIdentityValidationError
import com.github.traderjoe95.mls.protocol.error.CredentialValidationError
import com.github.traderjoe95.mls.protocol.error.IsSameClientError
import com.github.traderjoe95.mls.protocol.types.Credential
import com.github.traderjoe95.mls.protocol.types.crypto.SignaturePublicKey
import com.github.traderjoe95.mls.protocol.types.tree.LeafNode

interface AuthenticationService<Identity : Any> {
  suspend fun authenticateCredentialIdentity(
    identity: Identity,
    signaturePublicKey: SignaturePublicKey,
    credential: Credential,
  ): Either<CredentialIdentityValidationError, Unit>

  suspend fun authenticateCredential(
    signaturePublicKey: SignaturePublicKey,
    credential: Credential,
  ): Either<CredentialValidationError, Identity>

  suspend fun authenticateCredentials(
    vararg credentials: Pair<SignaturePublicKey, Credential>,
  ): List<Either<CredentialValidationError, Identity>> = authenticateCredentials(credentials.asList())

  suspend fun authenticateCredentials(
    credentials: Iterable<Pair<SignaturePublicKey, Credential>>,
  ): List<Either<CredentialValidationError, Identity>>

  suspend fun isSameClient(
    credentialA: Credential,
    credentialB: Credential,
  ): Either<IsSameClientError, Boolean>
}

suspend fun <Identity : Any> AuthenticationService<Identity>.authenticateCredential(
  leafNode: LeafNode<*>,
): Either<CredentialValidationError, Identity> = authenticateCredential(leafNode.signaturePublicKey, leafNode.credential)

suspend fun <Identity : Any> AuthenticationService<Identity>.authenticateCredentials(
  leafNodes: Iterable<LeafNode<*>>,
): List<Either<CredentialValidationError, Identity>> = authenticateCredentials(leafNodes.map { it.signaturePublicKey to it.credential })
