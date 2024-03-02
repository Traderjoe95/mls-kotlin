package com.github.traderjoe95.mls.protocol.error

import com.github.traderjoe95.mls.protocol.types.framing.Sender

sealed interface DecryptError : PrivateMessageRecipientError, WelcomeJoinError

sealed interface HpkeDecryptError : RecipientTreeUpdateError, WelcomeJoinError

sealed interface HpkeEncryptError : SenderTreeUpdateError, SenderCommitError

sealed interface ReconstructHpkePublicKeyError

sealed interface SendExportError : ExternalJoinError

sealed interface ReceiveExportError : CommitError

sealed interface MacError : RecipientCommitError, JoinError, MessageRecipientError {
  data object BadMac : MacError
}

sealed interface CreateSignatureError : SenderCommitError, GroupInfoError, SenderTreeUpdateError, MessageSenderError, GroupCreationError

sealed interface VerifySignatureError :
  JoinError,
  LeafNodeCheckError,
  MessageRecipientError,
  KeyPackageValidationError {
  data object BadSignature : VerifySignatureError

  data class SignaturePublicKeyKeyNotFound(val sender: Sender) : VerifySignatureError
}

sealed interface ReconstructSignaturePublicKeyError

data object AeadDecryptionFailed : DecryptError, HpkeDecryptError

data class MalformedPublicKey(val details: String?) : HpkeEncryptError, VerifySignatureError, SendExportError

data class MalformedPrivateKey(val details: String?) :
  HpkeDecryptError,
  ReceiveExportError,
  ReconstructHpkePublicKeyError,
  CreateSignatureError,
  ReconstructSignaturePublicKeyError
