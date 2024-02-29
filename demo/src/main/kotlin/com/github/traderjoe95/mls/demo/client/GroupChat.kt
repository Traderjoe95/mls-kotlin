package com.github.traderjoe95.mls.demo.client

import arrow.core.Either
import arrow.core.raise.Raise
import arrow.core.raise.either
import arrow.core.raise.recover
import com.github.traderjoe95.mls.demo.Config
import com.github.traderjoe95.mls.demo.getOrThrow
import com.github.traderjoe95.mls.demo.service.DeliveryService
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.error.BranchError
import com.github.traderjoe95.mls.protocol.error.GroupInfoError
import com.github.traderjoe95.mls.protocol.error.ProcessMessageError
import com.github.traderjoe95.mls.protocol.error.ReInitError
import com.github.traderjoe95.mls.protocol.error.RecipientCommitError
import com.github.traderjoe95.mls.protocol.error.SenderCommitError
import com.github.traderjoe95.mls.protocol.group.GroupState
import com.github.traderjoe95.mls.protocol.group.prepareCommit
import com.github.traderjoe95.mls.protocol.group.resumption.branchGroup
import com.github.traderjoe95.mls.protocol.group.resumption.createWelcome
import com.github.traderjoe95.mls.protocol.group.resumption.reInitGroup
import com.github.traderjoe95.mls.protocol.message.GroupMessage
import com.github.traderjoe95.mls.protocol.message.HandshakeMessage
import com.github.traderjoe95.mls.protocol.tree.findLeaf
import com.github.traderjoe95.mls.protocol.types.framing.content.Add
import com.github.traderjoe95.mls.protocol.types.framing.content.ApplicationData
import com.github.traderjoe95.mls.protocol.types.framing.content.AuthenticatedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.Remove
import com.github.traderjoe95.mls.protocol.types.framing.enums.ContentType

class GroupChat(
  val state: GroupState,
  private val client: Client,
) {
  init {
    DeliveryService.registerForGroup(state.groupId, client.userName)
  }

  suspend fun addMember(user: String): Either<SenderCommitError, GroupChat> =
    either {
      with(client) {
        state.ensureActive {
          prepareCommit(
            listOf(
              Add(DeliveryService.getKeyPackage(Config.protocolVersion, Config.cipherSuite, user).getOrThrow()),
            ),
          )
        }.let { (ctx, commit, newMemberWelcome) ->
          DeliveryService.sendMessageToGroup(commit, state.groupId, userName).getOrThrow()

          newMemberWelcome.forEach { (welcome, to) ->
            DeliveryService.sendMessageToIdentities(
              welcome,
              client.authenticateCredentials(to.map { it.leafNode.signaturePublicKey to it.leafNode.credential })
                .bindAll(),
            )
          }

          GroupChat(ctx, client).register()
        }
      }
    }

  suspend fun removeMember(user: String): Either<SenderCommitError, GroupChat> =
    either {
      with(client) {
        val (_, leafIndex) =
          state.tree.findLeaf {
            client.authenticateCredentialIdentity(user, signaturePublicKey, credential).isRight()
          } ?: error("User $user is not member of the group")

        state.ensureActive {
          prepareCommit(listOf(Remove(leafIndex)))
        }.let { (ctx, commit, _) ->
          DeliveryService.sendMessageToGroup(commit, state.groupId, userName).getOrThrow()

          GroupChat(ctx, client).register()
        }
      }
    }

  fun makePublic(): Either<GroupInfoError, Unit> =
    either {
      state.ensureActive {
        DeliveryService.storeGroupInfo(groupInfo(public = true))
      }
    }

  suspend fun reInit(cipherSuite: CipherSuite): Either<ReInitError, GroupChat> =
    either {
      with(client) {
        val (suspended, commit) =
          state.ensureActive {
            reInitGroup(cipherSuite = cipherSuite)
          }

        DeliveryService.sendMessageToGroup(commit, state.groupId, userName)

        GroupChat(suspended, client).register()
      }
    }

  suspend fun branch(vararg users: String): Either<BranchError, GroupChat> =
    either {
      with(client) {
        val (newGroup, newMemberWelcome) =
          state.ensureActive {
            branchGroup(
              newKeyPackage(cipherSuite),
              users.map { user ->
                tree.findLeaf {
                  client.authenticateCredentialIdentity(user, signaturePublicKey, credential).isRight()
                }?.second!!
              },
            )
          }

        newMemberWelcome.forEach { (welcome, to) ->
          DeliveryService.sendMessageToIdentities(
            welcome,
            client.authenticateCredentials(to.map { it.leafNode.signaturePublicKey to it.leafNode.credential })
              .bindAll(),
          )
        }

        GroupChat(newGroup, client).register()
      }
    }

  suspend fun createReInitGroup(): Either<ReInitError, GroupChat> =
    either {
      with(client) {
        val suspended = state as GroupState.Suspended
        val (newGroup, newMemberWelcome) =
          suspended.createWelcome(
            newKeyPackage(suspended.reInit.cipherSuite),
          )

        newMemberWelcome.forEach { (welcome, to) ->
          DeliveryService.sendMessageToIdentities(
            welcome,
            client.authenticateCredentials(to.map { it.leafNode.signaturePublicKey to it.leafNode.credential })
              .bindAll(),
          )
        }

        GroupChat(newGroup, client).register()
      }
    }

  suspend fun sendTextMessage(message: String) =
    either {
      DeliveryService.sendMessageToGroup(
        state.coerceActive().messages.applicationMessage(ApplicationData(message.encodeToByteArray())),
        state.groupId,
        client.userName,
      ).bind()
    }

  @Suppress("UNCHECKED_CAST")
  suspend fun processMessage(message: GroupMessage<*>): GroupChat =
    either {
      if (message.contentType == ContentType.Commit && message.epoch != state.epoch) {
        println("[${client.userName}] Received commit for wrong epoch, dropping")
        this@GroupChat
      } else if (message.contentType == ContentType.Proposal && message.epoch != state.epoch) {
        println("[${client.userName}] Received proposal for wrong epoch, dropping")
        this@GroupChat
      } else if (message.contentType is ContentType.Handshake) {
        processHandshakeMessage(message as HandshakeMessage)
      } else {
        processApplicationData(
          state.ensureActive { message.unprotect(this) } as AuthenticatedContent<ApplicationData>,
        )
      }
    }.getOrThrow()

  context(Raise<ProcessMessageError>)
  private suspend fun processHandshakeMessage(message: HandshakeMessage): GroupChat =
    with(client) {
      GroupChat(
        recover(
          block = {
            state.coerceActive().process(message, psks = client)
          },
          recover = {
//              if (it == RemovedFromGroup) DeliveryService.unregisterGroup(groupId, client.applicationId)
            raise(it)
          },
        ),
        client,
      ).register()
    }

  context(Raise<RecipientCommitError>)
  private fun processApplicationData(authContent: AuthenticatedContent<ApplicationData>): GroupChat =
    apply {
      println("[${client.userName}] ${authContent.content.content.bytes.decodeToString()}")
    }
}
