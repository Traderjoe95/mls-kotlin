@file:OptIn(ExperimentalStdlibApi::class)

package com.github.traderjoe95.mls.protocol.util

import com.github.traderjoe95.mls.protocol.crypto.KeySchedule
import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.group.GroupState
import com.github.traderjoe95.mls.protocol.types.Extension
import com.github.traderjoe95.mls.protocol.types.crypto.Ciphertext
import com.github.traderjoe95.mls.protocol.types.crypto.HpkeCiphertext
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePrivateKey
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePublicKey
import com.github.traderjoe95.mls.protocol.types.crypto.KemOutput
import com.github.traderjoe95.mls.protocol.types.crypto.Mac
import com.github.traderjoe95.mls.protocol.types.crypto.Nonce
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.crypto.Signature
import com.github.traderjoe95.mls.protocol.types.crypto.SigningKey
import com.github.traderjoe95.mls.protocol.types.crypto.VerificationKey

inline val ByteArray.hex: String
  get() = toHexString()

val Secret.hex: String
  get() = key.hex

val Nonce.hex: String
  get() = value.hex

val Ciphertext.hex: String
  get() = value.hex

val Signature.hex: String
  get() = value.hex

val Mac.hex: String
  get() = value.hex

val HpkePublicKey.hex: String
  get() = key.hex

val HpkePrivateKey.hex: String
  get() = key.hex

val VerificationKey.hex: String
  get() = key.hex

val SigningKey.hex: String
  get() = key.hex

val KemOutput.hex: String
  get() = value.hex

val HpkeCiphertext.debug: String
  get() = "(kemOutput=${kemOutput.hex}, ciphertext=${ciphertext.hex})"

val GroupState.debug: String
  get() =
    """MEMBER
      |Leaf Index: $ownLeafIndex
      |
      |GROUP CONTEXT
      |${groupContext.debug.prependIndent("  ")}
      |
      |KEY SCHEDULE
      |${(this.keySchedule).debug.prependIndent("  ")}
    """.trimMargin()

val GroupContext.debug: String
  get() =
    """Protocol Version:          $protocolVersion
      |Cipher Suite:              $cipherSuite
      |Group ID:                  $groupId
      |Epoch:                     $epoch
      |Tree Hash:                 ${treeHash.hex}
      |Confirmed Transcript Hash: ${confirmedTranscriptHash.hex}
      |Interim Transcript Hash:   ${interimTranscriptHash.hex}
      |Extensions:${if (extensions.isEmpty()) " <none>" else extensions.joinToString("\n  ", prefix = "\n  ")}
    """.trimMargin()

val KeySchedule.debug: String
  get() =
    """Epoch Secret:        ${epochSecret.hex}
      |Sender Data Secret:  ${senderDataSecret.hex}
      |Encryption Secret:   ${encryptionSecret.hex}
      |Exporter Secret:     ${exporterSecret.hex}
      |External Secret:     ${externalSecret.hex}
      |Confirmation Key:    ${confirmationKey.hex}
      |Membership Key:      ${membershipKey.hex}
      |Resumption PSK:      ${resumptionPsk.hex}
      |Epoch Authenticator: ${epochAuthenticator.hex}
    """.trimMargin()

val Extension<*>.debug: String
  get() = "$type: $this"
