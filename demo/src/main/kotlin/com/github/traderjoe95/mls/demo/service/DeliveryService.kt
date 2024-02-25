package com.github.traderjoe95.mls.demo.service

import arrow.core.Either
import arrow.core.raise.either
import com.github.traderjoe95.mls.codec.decodeAs
import com.github.traderjoe95.mls.demo.util.compute
import com.github.traderjoe95.mls.demo.util.get
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.error.DecoderError
import com.github.traderjoe95.mls.protocol.error.EncoderError
import com.github.traderjoe95.mls.protocol.error.GetGroupInfoError
import com.github.traderjoe95.mls.protocol.error.KeyPackageRetrievalError
import com.github.traderjoe95.mls.protocol.error.SendToGroupError
import com.github.traderjoe95.mls.protocol.error.SendToUserError
import com.github.traderjoe95.mls.protocol.error.UnknownGroup
import com.github.traderjoe95.mls.protocol.error.UnknownUser
import com.github.traderjoe95.mls.protocol.message.GroupInfo
import com.github.traderjoe95.mls.protocol.message.KeyPackage
import com.github.traderjoe95.mls.protocol.message.MlsMessage
import com.github.traderjoe95.mls.protocol.message.MlsMessage.Companion.encode
import com.github.traderjoe95.mls.protocol.service.DeliveryService
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion
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
  private val groups: ConcurrentMap<Int, GroupView> = ConcurrentHashMap()

  private val keyPackages: ConcurrentMap<Triple<String, ProtocolVersion, CipherSuite>, ConcurrentLinkedQueue<ByteArray>> =
    ConcurrentHashMap()

  fun registerUser(user: String): Channel<Pair<ULID, ByteArray>> = users.computeIfAbsent(user) { Channel(UNLIMITED) }

  fun registerForGroup(
    group: GroupId,
    user: String,
  ) {
    groups.compute(group) { _, view ->
      view?.copy(members = view.members + user) ?: GroupView(setOf(user))
    }
  }

  fun unregisterFromGroup(
    group: GroupId,
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
    toGroup: GroupId,
    fromUser: String,
  ): Either<SendToGroupError, ULID> =
    either {
      val encoded = EncoderError.wrap { message.encode().bind() }
      val messageId = ULID.new()

      groups[toGroup]?.members?.forEach {
        if (it != fromUser) users[it]?.send(messageId to encoded)
      } ?: raise(UnknownGroup(toGroup))

      messageId
    }

  suspend fun sendMessageToGroup(
    message: MlsMessage<*>,
    toGroup: GroupId,
  ): Either<SendToGroupError, ULID> =
    either {
      val encoded = EncoderError.wrap { message.encode().bind() }
      val messageId = ULID.new()

      groups[toGroup]?.members?.forEach {
        users[it]?.send(messageId to encoded)
      } ?: raise(UnknownGroup(toGroup))

      messageId
    }

  suspend fun sendMessageToIdentity(
    message: MlsMessage<*>,
    to: String,
  ): Either<SendToUserError<String>, ULID> =
    either {
      val encoded = EncoderError.wrap { message.encode().bind() }
      val messageId = ULID.new()

      users[to]?.send(messageId to encoded) ?: raise(UnknownUser(to))

      messageId
    }

  suspend fun sendMessageToIdentities(
    message: MlsMessage<*>,
    to: List<String>,
  ): Map<String, Either<SendToUserError<String>, ULID>> {
    val encoded =
      either {
        EncoderError.wrap { message.encode().bind() }
      }

    return to.associateWith { toUser ->
      val messageId = ULID.new()

      either {
        users[toUser]?.send(messageId to encoded.bind()) ?: raise(UnknownUser(toUser))
        messageId
      }
    }
  }

  override suspend fun getPublicGroupInfo(groupId: GroupId): Either<GetGroupInfoError, GroupInfo> =
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
