package com.github.traderjoe95.mls.protocol.interop.crypto

import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.crypto.KeySchedule
import com.github.traderjoe95.mls.protocol.group.GroupContext
import com.github.traderjoe95.mls.protocol.group.GroupContext.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.interop.util.getCipherSuite
import com.github.traderjoe95.mls.protocol.interop.util.getGroupId
import com.github.traderjoe95.mls.protocol.interop.util.getHexBinary
import com.github.traderjoe95.mls.protocol.interop.util.getHpkePublicKey
import com.github.traderjoe95.mls.protocol.interop.util.getSecret
import com.github.traderjoe95.mls.protocol.interop.util.getUShort
import com.github.traderjoe95.mls.protocol.interop.util.nextString
import com.github.traderjoe95.mls.protocol.interop.util.nextUShort
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePublicKey
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion
import io.vertx.core.Vertx
import io.vertx.core.json.JsonObject
import io.vertx.kotlin.core.json.get
import io.vertx.kotlin.coroutines.coAwait
import kotlin.random.Random
import kotlin.random.nextInt

data class KeyScheduleTestVector(
  val cipherSuite: CipherSuite,
  val groupId: GroupId,
  val initialInitSecret: Secret,
  val epochs: List<Epoch>,
) {
  constructor(json: JsonObject) : this(
    json.getCipherSuite("cipher_suite"),
    json.getGroupId("group_id"),
    json.getSecret("initial_init_secret"),
    json.getJsonArray("epochs").map { Epoch(it as JsonObject, CipherSuite(json.getUShort("cipher_suite"))!!) },
  )

  companion object {
    suspend fun load(
      vertx: Vertx,
      file: String = "testvectors/key-schedule.json",
    ): List<KeyScheduleTestVector> =
      vertx.fileSystem()
        .readFile(file)
        .coAwait()
        .toJsonArray()
        .map { KeyScheduleTestVector(it as JsonObject) }

    fun generate(
      cipherSuite: CipherSuite,
      numOfEpochs: UInt,
    ): KeyScheduleTestVector {
      val groupId = GroupId.new()
      val initialInit = cipherSuite.generateSecret(cipherSuite.hashLen)

      val epochs =
        sequence {
          var keySchedule = KeySchedule.uninitialized(cipherSuite, initialInit.copy())

          for (epoch in 0UL..<numOfEpochs.toULong()) {
            val groupContext =
              GroupContext(
                ProtocolVersion.MLS_1_0,
                cipherSuite,
                groupId,
                epoch,
                cipherSuite.generateSecret(cipherSuite.hashLen).bytes,
                cipherSuite.generateSecret(cipherSuite.hashLen).bytes,
              )
            val commitSecret = cipherSuite.generateSecret(cipherSuite.hashLen)
            val pskSecret = cipherSuite.generateSecret(cipherSuite.hashLen)

            val (newKeySchedule, joinerSecret, welcomeSecret) = keySchedule.next(commitSecret, groupContext, pskSecret)
            keySchedule = newKeySchedule

            val exporterLabel = Random.nextString()
            val exporterContext = Random.nextBytes(Random.nextInt(0..64))
            val exporterLength = Random.nextUShort(16U..128U)

            yield(
              Epoch(
                groupContext.treeHash,
                commitSecret,
                pskSecret,
                groupContext.confirmedTranscriptHash,
                groupContext.encodeUnsafe(),
                joinerSecret,
                welcomeSecret,
                keySchedule.initSecret.copy(),
                keySchedule.senderDataSecret,
                keySchedule.encryptionSecret,
                keySchedule.exporterSecret,
                keySchedule.epochAuthenticator,
                keySchedule.externalSecret,
                keySchedule.confirmationKey,
                keySchedule.membershipKey,
                keySchedule.resumptionPsk,
                cipherSuite.deriveKeyPair(keySchedule.externalSecret).public,
                Exporter(
                  exporterLabel,
                  exporterContext,
                  exporterLength,
                  keySchedule.mlsExporter(exporterLabel, exporterContext, exporterLength),
                ),
              ),
            )
          }
        }.toList()

      return KeyScheduleTestVector(
        cipherSuite,
        groupId,
        initialInit,
        epochs,
      )
    }
  }

  data class Epoch(
    // Generated
    val treeHash: ByteArray,
    val commitSecret: Secret,
    val pskSecret: Secret,
    val confirmedTranscriptHash: ByteArray,
    // Computed
    val groupContext: ByteArray,
    val joinerSecret: Secret,
    val welcomeSecret: Secret,
    val initSecret: Secret,
    val senderDataSecret: Secret,
    val encryptionSecret: Secret,
    val exporterSecret: Secret,
    val epochAuthenticator: Secret,
    val externalSecret: Secret,
    val confirmationKey: Secret,
    val membershipKey: Secret,
    val resumptionPsk: Secret,
    // Derived
    val externalPub: HpkePublicKey,
    val exporter: Exporter,
  ) {
    constructor(json: JsonObject, cipherSuite: CipherSuite) : this(
      json.getHexBinary("tree_hash"),
      json.getSecret("commit_secret"),
      json.getSecret("psk_secret", Secret.zeroes(cipherSuite.hashLen)),
      json.getHexBinary("confirmed_transcript_hash"),
      json.getHexBinary("group_context"),
      json.getSecret("joiner_secret"),
      json.getSecret("welcome_secret"),
      json.getSecret("init_secret"),
      json.getSecret("sender_data_secret"),
      json.getSecret("encryption_secret"),
      json.getSecret("exporter_secret"),
      json.getSecret("epoch_authenticator"),
      json.getSecret("external_secret"),
      json.getSecret("confirmation_key"),
      json.getSecret("membership_key"),
      json.getSecret("resumption_psk"),
      json.getHpkePublicKey("external_pub"),
      Exporter(json["exporter"]),
    )
  }

  data class Exporter(
    val label: String,
    val context: ByteArray,
    val length: UShort,
    val secret: Secret,
  ) {
    constructor(json: JsonObject) : this(
      json["label"],
      json.getHexBinary("context"),
      json.getUShort("length"),
      json.getSecret("secret"),
    )
  }
}
