package com.github.traderjoe95.mls.playground

import arrow.core.Either
import arrow.core.raise.Raise
import arrow.core.raise.either
import arrow.core.raise.recover
import com.github.traderjoe95.mls.playground.service.DeliveryService
import com.github.traderjoe95.mls.protocol.error.EncoderError
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
  private val state: GroupState,
  private val client: Client,
) : GroupState by state {
  init {
    DeliveryService.registerGroup(groupId, client.userName)
  }

  suspend fun addMember(user: String): Either<SenderCommitError, GroupChat> =
    either {
      with(client) {
        state.prepareCommit(
          listOf(
            Add(DeliveryService.getKeyPackage(Config.protocolVersion, Config.cipherSuite, user).getOrThrow()),
          ),
        ).let { (ctx, commit, _, welcome) ->
          client.sendMessageToGroup(commit, groupId).getOrThrow()
          client.sendMessageToUser(welcome!!, user).getOrThrow()

          GroupChat(ctx, client).register()
        }
      }
    }

  suspend fun removeMember(user: String): Either<SenderCommitError, GroupChat> =
    either {
      with(client) {
        val (_, leafIndex) =
          tree.findLeaf {
            client.authenticateCredentialIdentity(user, this).isRight()
          } ?: error("User $user is not member of the group")

        state.prepareCommit(
          listOf(Remove(leafIndex)),
        ).let { (ctx, commit, _, _) ->
          client.sendMessageToGroup(commit, groupId).getOrThrow()

          GroupChat(ctx, client).register()
        }
      }
    }

  suspend fun sendPrivateApplicationMessage(message: String) =
    either {
      client.sendMessageToGroup(
        MlsMessage.private(ApplicationData(message.encodeToByteArray())),
        groupId,
      ).bind()
    }

  suspend fun sendPublicApplicationMessage(message: String) =
    either {
      client.sendMessageToGroup(
        MlsMessage.public(ApplicationData(message.encodeToByteArray())),
        groupId,
      ).bind()
    }

  suspend fun processMessage(message: GroupMessage<*>): GroupChat =
    either {
      if (message.contentType == ContentType.Commit && message.epoch != currentEpoch) {
        println("[${client.userName}] Received commit for wrong epoch, dropping")
        this@GroupChat
      } else if (message.contentType == ContentType.Proposal && message.epoch != currentEpoch) {
        println("[${client.userName}] Received proposal for wrong epoch, dropping")
        this@GroupChat
      } else {
        processAuthenticatedContent(message.getAuthenticatedContent())
      }
    }.getOrThrow()

  context(Raise<RecipientCommitError>)
  private suspend fun processAuthenticatedContent(authContent: AuthenticatedContent<*>): GroupChat =
    when (val body = authContent.content.content) {
      is Commit ->
        with(client) {
          println("[${client.userName}] Commit for $groupId: ${body.proposals}")
          @Suppress("UNCHECKED_CAST")
          GroupChat(
            recover(
              block = { processCommit(authContent as AuthenticatedContent<Commit>) },
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
          EncoderError.wrap {
            println("[${client.userName}] Proposal for $groupId: $body")
            storeProposal(body, authContent.sender.index)
          }
        }

      is ApplicationData ->
        apply {
          println("[${client.userName}] ${body.data.decodeToString()}")
        }
    }
}
