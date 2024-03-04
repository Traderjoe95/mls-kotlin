@file:OptIn(ExperimentalStdlibApi::class)

package com.github.traderjoe95.mls.protocol.util

import com.github.traderjoe95.mls.protocol.crypto.KeySchedule
import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.group.GroupState
import com.github.traderjoe95.mls.protocol.types.Extension
import com.github.traderjoe95.mls.protocol.types.RefinedBytes
import com.github.traderjoe95.mls.protocol.types.crypto.HpkeCiphertext

inline val ByteArray.hex: String
  get() = toHexString()

val RefinedBytes<*>.hex: String
  get() = bytes.hex

val HpkeCiphertext.debug: String
  get() = "(kemOutput=${kemOutput.hex}, ciphertext=${ciphertext.hex})"

val GroupState.debug: String
  get() =
    """MEMBER
      |Leaf Index: $leafIndex
      |Group Active: ${isActive()}
      |
      |GROUP CONTEXT
      |${groupContext.debug.prependIndent("  ")}
      |
      |KEY SCHEDULE
      |${keySchedule.debug.prependIndent("  ")}
    """.trimMargin()

val GroupContext.debug: String
  get() =
    """Protocol Version:          $protocolVersion
      |Cipher Suite:              $cipherSuite
      |Group ID:                  ${groupId.hex}
      |Epoch:                     $epoch
      |Tree Hash:                 ${treeHash.hex}
      |Confirmed Transcript Hash: ${confirmedTranscriptHash.hex}
      |Interim Transcript Hash:   ${interimTranscriptHash.hex}
      |Extensions:${if (extensions.isEmpty()) " <none>" else extensions.joinToString("\n  ", prefix = "\n  ")}
    """.trimMargin()

val KeySchedule.debug: String
  get() =
    """Sender Data Secret:  ${senderDataSecret.hex}
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
