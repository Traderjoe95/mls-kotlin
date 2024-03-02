package com.github.traderjoe95.mls.protocol.group

import arrow.core.Either
import arrow.core.raise.Raise
import arrow.core.raise.either
import arrow.core.right
import com.github.traderjoe95.mls.protocol.crypto.KeySchedule
import com.github.traderjoe95.mls.protocol.error.CredentialIdentityValidationError
import com.github.traderjoe95.mls.protocol.error.CredentialValidationError
import com.github.traderjoe95.mls.protocol.error.IsSameClientError
import com.github.traderjoe95.mls.protocol.error.PskError
import com.github.traderjoe95.mls.protocol.interop.group.PassiveClientTestVector
import com.github.traderjoe95.mls.protocol.message.CommitMessage
import com.github.traderjoe95.mls.protocol.message.MlsMessage.Companion.coerceFormat
import com.github.traderjoe95.mls.protocol.message.ProposalMessage
import com.github.traderjoe95.mls.protocol.psk.ExternalPskId
import com.github.traderjoe95.mls.protocol.psk.PreSharedKeyId
import com.github.traderjoe95.mls.protocol.psk.PskLookup
import com.github.traderjoe95.mls.protocol.psk.ResumptionPskId
import com.github.traderjoe95.mls.protocol.service.AuthenticationService
import com.github.traderjoe95.mls.protocol.testing.VertxFunSpec
import com.github.traderjoe95.mls.protocol.testing.shouldBeEq
import com.github.traderjoe95.mls.protocol.types.Credential
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.crypto.SignaturePublicKey
import com.github.traderjoe95.mls.protocol.util.foldWith
import com.github.traderjoe95.mls.protocol.util.unsafe
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.core.factory.TestFactory
import io.kotest.core.spec.style.funSpec
import io.kotest.matchers.types.shouldBeInstanceOf
import io.vertx.core.Vertx

class PassiveClientScenarios : VertxFunSpec({ vertx ->
  include(scenario(vertx, "welcome"))
  include(scenario(vertx, "handling-commit"))
  include(scenario(vertx, "random"))
}) {
  companion object {
    fun scenario(
      vertx: Vertx,
      name: String,
    ): TestFactory =
      funSpec {
        context("In the '$name' scenario") {
          val allTestVectors = PassiveClientTestVector.load(vertx, "testvectors/passive-client-$name.json")

          allTestVectors.groupBy { it.cipherSuite }.toSortedMap().forEach { (cipherSuite, testVectors) ->
            context("with cipher suite $cipherSuite") {
              testVectors.forEachIndexed { idx, v ->
                context("in example ${idx + 1}") example@{
                  test("the client should be able to join the group") {
                    var state =
                      either {
                        v.welcome.message.joinGroup(
                          v.privateKeyPackage,
                          AuthenticationSvc,
                          psks = v.externalPsks.asPskLookup(null),
                          optionalTree = v.ratchetTree,
                        ).bind()
                      }.shouldBeRight().shouldBeInstanceOf<GroupState.Active>()

                    state.keySchedule.epochAuthenticator shouldBeEq v.initialEpochAuthenticator
                    val firstEpoch = state.epoch.toLong()
                    val keySchedules = mutableMapOf(state.epoch to state.keySchedule)
                    val pskLookup = v.externalPsks.asPskLookup(state.groupId, keySchedules)

                    v.epochs.forEachIndexed { idx, epoch ->
                      this@example.context("in epoch ${firstEpoch + idx}") {
                        test("the commit should be successfully applied") {
                          state =
                            state.foldWith(epoch.proposals) {
                              unsafe {
                                process(it.coerceFormat<ProposalMessage>().message, AuthenticationSvc).bind()
                              }.shouldBeInstanceOf<GroupState.Active>()
                            }

                          state =
                            unsafe {
                              state.process(
                                epoch.commit.coerceFormat<CommitMessage>().message,
                                AuthenticationSvc,
                                pskLookup,
                              ).bind()
                            }.shouldBeInstanceOf<GroupState.Active>()

                          keySchedules[state.epoch] = state.keySchedule
                        }

                        test("and the epoch authenticator should be as expected") {
                          state.keySchedule.epochAuthenticator shouldBeEq epoch.epochAuthenticator
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }

    fun List<PassiveClientTestVector.ExternalPsk>.asPskLookup(
      groupId: GroupId?,
      oldKeySchedules: Map<ULong, KeySchedule> = mapOf(),
    ): PskLookup =
      object : PskLookup {
        context(Raise<PskError>)
        override suspend fun resolvePsk(id: PreSharedKeyId): Secret =
          when (id) {
            is ExternalPskId ->
              this@asPskLookup
                .find { it.pskId.contentEquals(id.pskId) }
                ?.psk
                ?: raise(PskError.PskNotFound(id))

            is ResumptionPskId ->
              if (groupId != null && id.pskGroupId eq groupId) {
                oldKeySchedules[id.pskEpoch]
                  ?.resumptionPsk
                  ?: raise(PskError.PskNotFound(id))
              } else {
                raise(PskError.PskNotFound(id))
              }
          }
      }

    object AuthenticationSvc : AuthenticationService<ByteArray> {
      override suspend fun authenticateCredentialIdentity(
        identity: ByteArray,
        signaturePublicKey: SignaturePublicKey,
        credential: Credential,
      ): Either<CredentialIdentityValidationError, Unit> = Unit.right()

      override suspend fun authenticateCredential(
        signaturePublicKey: SignaturePublicKey,
        credential: Credential,
      ): Either<CredentialValidationError, ByteArray> = byteArrayOf().right()

      override suspend fun authenticateCredentials(
        credentials: Iterable<Pair<SignaturePublicKey, Credential>>,
      ): List<Either<CredentialValidationError, ByteArray>> = credentials.map { byteArrayOf().right() }

      override suspend fun isSameClient(
        credentialA: Credential,
        credentialB: Credential,
      ): Either<IsSameClientError, Boolean> = false.right()
    }
  }
}
