package com.github.traderjoe95.mls.protocol.interop.group

import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.group.newConfirmedTranscriptHash
import com.github.traderjoe95.mls.protocol.group.newInterimTranscriptHash
import com.github.traderjoe95.mls.protocol.interop.util.choice
import com.github.traderjoe95.mls.protocol.interop.util.getCipherSuite
import com.github.traderjoe95.mls.protocol.interop.util.getHexBinary
import com.github.traderjoe95.mls.protocol.interop.util.getSecret
import com.github.traderjoe95.mls.protocol.interop.util.nextCommit
import com.github.traderjoe95.mls.protocol.tree.LeafIndex
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.framing.content.AuthenticatedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.FramedContent
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion
import com.github.traderjoe95.mls.protocol.types.framing.enums.WireFormat
import com.github.traderjoe95.mls.protocol.util.unsafe
import io.vertx.core.Vertx
import io.vertx.core.json.JsonObject
import io.vertx.kotlin.coroutines.coAwait
import kotlin.random.Random
import kotlin.random.nextULong

data class TranscriptHashesTestVector(
  val cipherSuite: CipherSuite,
  // Generated
  val confirmationKey: Secret,
  val authenticatedContent: AuthenticatedContent<*>,
  val interimTranscriptHashBefore: ByteArray,
  // Calculated
  val confirmedTranscriptHashAfter: ByteArray,
  val interimTranscriptHashAfter: ByteArray,
) {
  constructor(json: JsonObject) : this(
    json.getCipherSuite("cipher_suite"),
    json.getSecret("confirmation_key"),
    AuthenticatedContent.decodeUnsafe(json.getHexBinary("authenticated_content")),
    json.getHexBinary("interim_transcript_hash_before"),
    json.getHexBinary("confirmed_transcript_hash_after"),
    json.getHexBinary("interim_transcript_hash_after"),
  )

  companion object {
    suspend fun load(
      vertx: Vertx,
      file: String = "testvectors/transcript-hashes.json",
    ): List<TranscriptHashesTestVector> =
      vertx.fileSystem()
        .readFile(file)
        .coAwait()
        .toJsonArray()
        .map { TranscriptHashesTestVector(it as JsonObject) }

    fun generate(cipherSuite: CipherSuite): TranscriptHashesTestVector {
      val confirmationKey = cipherSuite.generateSecret(cipherSuite.hashLen)
      val signingKey = cipherSuite.generateSignatureKeyPair().private
      val interimTranscriptHashBefore = Random.nextBytes(cipherSuite.hashLen.toInt())

      val wireFormat = Random.choice(listOf(WireFormat.MlsPublicMessage, WireFormat.MlsPrivateMessage))

      val groupContext =
        GroupContext(
          ProtocolVersion.MLS_1_0,
          cipherSuite,
          GroupId.new(),
          Random.nextULong(),
          Random.nextBytes(cipherSuite.hashLen.toInt()),
          byteArrayOf(),
          listOf(),
        )

      val commit = Random.nextCommit(cipherSuite, groupContext.groupId)
      val commitContent = FramedContent.createMember(commit, groupContext, LeafIndex(1U))

      val signature = unsafe { commitContent.sign(wireFormat, groupContext, signingKey).bind() }

      val confirmedTranscriptHashAfter =
        newConfirmedTranscriptHash(
          cipherSuite,
          interimTranscriptHashBefore,
          wireFormat,
          commitContent,
          signature,
        )

      val confirmationTag = cipherSuite.mac(confirmationKey, confirmedTranscriptHashAfter)

      val commitAuthenticatedContent = AuthenticatedContent(wireFormat, commitContent, signature, confirmationTag)
      val interimTranscriptHashAfter =
        newInterimTranscriptHash(cipherSuite, confirmedTranscriptHashAfter, confirmationTag)

      return TranscriptHashesTestVector(
        cipherSuite,
        confirmationKey,
        commitAuthenticatedContent,
        interimTranscriptHashBefore,
        confirmedTranscriptHashAfter,
        interimTranscriptHashAfter,
      )
    }
  }
}
