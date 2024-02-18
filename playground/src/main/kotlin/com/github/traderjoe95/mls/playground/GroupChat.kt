package com.github.traderjoe95.mls.playground

import arrow.core.Either
import arrow.core.raise.Raise
import arrow.core.raise.either
import arrow.core.raise.recover
import com.github.traderjoe95.mls.playground.service.DeliveryService
import com.github.traderjoe95.mls.protocol.error.GroupInfoError
import com.github.traderjoe95.mls.protocol.error.RecipientCommitError
import com.github.traderjoe95.mls.protocol.error.SenderCommitError
import com.github.traderjoe95.mls.protocol.group.GroupState
import com.github.traderjoe95.mls.protocol.group.prepareCommit
import com.github.traderjoe95.mls.protocol.group.processCommit
import com.github.traderjoe95.mls.protocol.tree.findLeaf
import com.github.traderjoe95.mls.protocol.types.framing.MlsMessage
import com.github.traderjoe95.mls.protocol.types.framing.content.Add
import com.github.traderjoe95.mls.protocol.types.framing.content.ApplicationData
import com.github.traderjoe95.mls.protocol.types.framing.content.AuthenticatedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.Commit
import com.github.traderjoe95.mls.protocol.types.framing.content.Proposal
import com.github.traderjoe95.mls.protocol.types.framing.content.Remove
import com.github.traderjoe95.mls.protocol.types.framing.enums.ContentType
import com.github.traderjoe95.mls.protocol.types.framing.message.GroupMessage

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
        state.prepareCommit(
          listOf(
            Add(DeliveryService.getKeyPackage(Config.protocolVersion, Config.cipherSuite, user).getOrThrow()),
          ),
        ).let { (ctx, commit, welcome) ->
          client.sendMessageToGroup(commit, state.groupId).getOrThrow()
          client.sendMessageToUser(welcome!!, user).getOrThrow()

          GroupChat(ctx, client).register()
        }
      }
    }

  suspend fun removeMember(user: String): Either<SenderCommitError, GroupChat> =
    either {
      with(client) {
        val (_, leafIndex) =
          state.tree.findLeaf {
            client.authenticateCredentialIdentity(user, this).isRight()
          } ?: error("User $user is not member of the group")

        state.prepareCommit(
          listOf(Remove(leafIndex)),
        ).let { (ctx, commit, _) ->
          client.sendMessageToGroup(commit, state.groupId).getOrThrow()

          GroupChat(ctx, client).register()
        }
      }
    }

  fun makePublic(): Either<GroupInfoError, Unit> =
    either {
      DeliveryService.storeGroupInfo(state.groupInfo(public = true))
    }

  suspend fun sendPrivateApplicationMessage(message: String) =
    either {
      client.sendMessageToGroup(
        with(state) { MlsMessage.private(ApplicationData(message.encodeToByteArray())) },
        state.groupId,
      ).bind()
    }

  suspend fun sendPublicApplicationMessage(message: String) =
    either {
      client.sendMessageToGroup(
        with(state) { MlsMessage.public(ApplicationData(message.encodeToByteArray())) },
        state.groupId,
      ).bind()
    }

  suspend fun processMessage(message: GroupMessage<*>): GroupChat =
    either {
      if (message.contentType == ContentType.Commit && message.epoch != state.currentEpoch) {
        println("[${client.userName}] Received commit for wrong epoch, dropping")
        this@GroupChat
      } else if (message.contentType == ContentType.Proposal && message.epoch != state.currentEpoch) {
        println("[${client.userName}] Received proposal for wrong epoch, dropping")
        this@GroupChat
      } else {
        processAuthenticatedContent(with(state) { message.getAuthenticatedContent() })
      }
    }.getOrThrow()

  context(Raise<RecipientCommitError>)
  private suspend fun processAuthenticatedContent(authContent: AuthenticatedContent<*>): GroupChat =
    when (val body = authContent.content.content) {
      is Commit ->
        with(client) {
          println("[${client.userName}] Commit for ${state.groupId}: ${body.proposals}")
          @Suppress("UNCHECKED_CAST")
          GroupChat(
            recover(
              block = { state.processCommit(authContent as AuthenticatedContent<Commit>) },
              recover = {
//              if (it == RemovedFromGroup) DeliveryService.unregisterGroup(groupId, client.applicationId)

                raise(it)
              },
            ),
            client,
          ).register()
        }

      is Proposal ->
        apply {
          println("[${client.userName}] Proposal for ${state.groupId}: $body")
          state.storeProposal(body, authContent.sender.index)
        }

      is ApplicationData ->
        apply {
          println("[${client.userName}] ${body.data.decodeToString()}")
        }
    }
}
