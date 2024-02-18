package com.github.traderjoe95.mls.protocol.error

import arrow.core.raise.Raise
import arrow.core.raise.recover
import de.traderjoe.ulid.ULID
import com.github.traderjoe95.mls.codec.error.DecoderError as BaseDecoderError
import com.github.traderjoe95.mls.codec.error.EncoderError as BaseEncoderError

inline fun <E, F, T> Raise<E>.wrapErrors(
  crossinline wrap: (F) -> E,
  block: Raise<F>.() -> T,
): T = recover({ this.block() }) { raise(wrap(it)) }

data class EncoderError(
  val encoderError: BaseEncoderError,
) : SendError {
  companion object {
    context(Raise<EncoderError>)
    inline fun <T> wrap(block: Raise<BaseEncoderError>.() -> T): T = wrapErrors(::EncoderError, block)
  }
}

data class DecoderError(
  val decoderError: BaseDecoderError,
) : SignatureError, JoinError, MessageRecipientError, KeyPackageRetrievalError<Nothing> {
  companion object {
    context(Raise<DecoderError>)
    inline fun <T> wrap(block: Raise<BaseDecoderError>.() -> T): T = wrapErrors(::DecoderError, block)
  }
}

data class UnexpectedError(val details: String?) : AuthenticationServiceError, DeliveryServiceError

data class UnknownGroup(val groupId: ULID) :
  ResumptionPskError,
  ResumptionJoinError,
  SendToGroupError,
  GetGroupInfoError

data class GroupSuspended(val groupId: ULID) : CommitError, PrivateMessageSenderError, PublicMessageSenderError, GroupInfoError
