package com.github.traderjoe95.mls.playground.service

import arrow.core.Either
import arrow.core.left
import arrow.core.raise.either
import com.github.traderjoe95.mls.codec.decodeAs
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.error.DecoderError
import com.github.traderjoe95.mls.protocol.error.EncoderError
import com.github.traderjoe95.mls.protocol.error.GetGroupInfoError
import com.github.traderjoe95.mls.protocol.error.KeyPackageRetrievalError
import com.github.traderjoe95.mls.protocol.error.SendToGroupError
import com.github.traderjoe95.mls.protocol.error.SendToUserError
import com.github.traderjoe95.mls.protocol.error.UnexpectedError
import com.github.traderjoe95.mls.protocol.error.UnknownGroup
import com.github.traderjoe95.mls.protocol.error.UnknownUser
import com.github.traderjoe95.mls.protocol.service.DeliveryService
import com.github.traderjoe95.mls.protocol.types.framing.MlsMessage
import com.github.traderjoe95.mls.protocol.types.framing.MlsMessage.Companion.encode
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion
import com.github.traderjoe95.mls.protocol.types.framing.message.GroupInfo
import com.github.traderjoe95.mls.protocol.types.framing.message.KeyPackage
import de.traderjoe.ulid.ULID
import de.traderjoe.ulid.suspending.new
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.Channel.Factory.UNLIMITED
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.ConcurrentMap
import com.github.traderjoe95.mls.codec.error.EncoderError as BaseEncoderError

object DeliveryService : DeliveryService<String> {
  private val users: ConcurrentMap<String, Channel<Pair<ULID, ByteArray>>> = ConcurrentHashMap()
  private val groups: ConcurrentMap<ULID, GroupView> = ConcurrentHashMap()

  private val keyPackages: ConcurrentMap<Triple<String, ProtocolVersion, CipherSuite>, ConcurrentLinkedQueue<ByteArray>> =
    ConcurrentHashMap()

  fun registerUser(user: String): Channel<Pair<ULID, ByteArray>> = users.computeIfAbsent(user) { Channel(UNLIMITED) }

  fun registerForGroup(
    group: ULID,
    user: String,
  ) {
    groups.compute(group) { _, view ->
      view?.copy(members = view.members + user) ?: GroupView(setOf(user))
    }
  }

  fun unregisterFromGroup(
    group: ULID,
    user: String,
  ) {
    groups.compute(group) { _, view ->
      view?.copy(members = view.members - user) ?: view
    }
  }

  fun storeGroupInfo(groupInfo: GroupInfo) {
    groups.compute(groupInfo.groupContext.groupId) { _, view ->
      view?.copy(info = groupInfo) ?: GroupView(info = groupInfo)
    }
  }

  fun addKeyPackage(
    user: String,
    keyPackage: KeyPackage,
  ): Either<BaseEncoderError, Unit> =
    either {
      keyPackages.computeIfAbsent(Triple(user, keyPackage.version, keyPackage.cipherSuite)) { ConcurrentLinkedQueue() }
        .offer(KeyPackage.dataT.encode(keyPackage))
    }

  suspend fun sendMessageToGroup(
    message: MlsMessage<*>,
    toGroup: ULID,
    fromUser: String,
  ): Either<SendToGroupError, ULID> =
    either {
      val encoded = EncoderError.wrap { message.encode() }
      val messageId = ULID.new()

      groups[toGroup]?.members?.forEach {
        if (it != fromUser) users[it]?.send(messageId to encoded)
      } ?: raise(UnknownGroup(toGroup))

      messageId
    }

  override suspend fun sendMessageToGroup(
    message: MlsMessage<*>,
    toGroup: ULID,
  ): Either<SendToGroupError, ULID> = UnexpectedError("This implementation should not be called").left()

  override suspend fun sendMessageToUser(
    message: MlsMessage<*>,
    toUser: String,
  ): Either<SendToUserError<String>, ULID> =
    either {
      val encoded = EncoderError.wrap { message.encode() }
      val messageId = ULID.new()

      users[toUser]?.send(messageId to encoded) ?: raise(UnknownUser(toUser))

      messageId
    }

  override suspend fun sendMessageToUsers(
    message: MlsMessage<*>,
    toUsers: List<String>,
  ): Map<String, Either<SendToUserError<String>, ULID>> {
    val encoded =
      either {
        EncoderError.wrap { message.encode() }
      }

    return toUsers.associateWith { toUser ->
      val messageId = ULID.new()

      either {
        users[toUser]?.send(messageId to encoded.bind()) ?: raise(UnknownUser(toUser))
        messageId
      }
    }
  }

  override suspend fun getPublicGroupInfo(groupId: ULID): Either<GetGroupInfoError, GroupInfo> =
    either {
      groups[groupId]
        ?.run { info ?: raise(GetGroupInfoError.GroupNotPublic(groupId)) }
        ?: raise(UnknownGroup(groupId))
    }

  override suspend fun getKeyPackage(
    protocolVersion: ProtocolVersion,
    cipherSuite: CipherSuite,
    forUser: String,
  ): Either<KeyPackageRetrievalError<String>, KeyPackage> =
    either {
      DecoderError.wrap {
        keyPackages.computeIfAbsent(Triple(forUser, protocolVersion, cipherSuite)) { ConcurrentLinkedQueue() }
          .poll()
          ?.decodeAs(KeyPackage.dataT)
          ?: raise(KeyPackageRetrievalError.NoKeyPackage(protocolVersion, cipherSuite))
      }
    }

  override suspend fun getKeyPackages(
    protocolVersion: ProtocolVersion,
    cipherSuite: CipherSuite,
    forUsers: List<String>,
  ): Map<String, Either<KeyPackageRetrievalError<String>, KeyPackage>> =
    forUsers.associateWith { getKeyPackage(protocolVersion, cipherSuite, it) }

  data class GroupView(
    val members: Set<String> = setOf(),
    val info: GroupInfo? = null,
  )
}
