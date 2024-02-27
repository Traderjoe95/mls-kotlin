package com.github.traderjoe95.mls.protocol.interop.util

import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.types.GroupId
import com.github.traderjoe95.mls.protocol.types.GroupId.Companion.asGroupId
import com.github.traderjoe95.mls.protocol.types.crypto.Ciphertext
import com.github.traderjoe95.mls.protocol.types.crypto.Ciphertext.Companion.asCiphertext
import com.github.traderjoe95.mls.protocol.types.crypto.HashReference
import com.github.traderjoe95.mls.protocol.types.crypto.HashReference.Companion.asHashReference
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePrivateKey
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePrivateKey.Companion.asHpkePrivateKey
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePublicKey
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePublicKey.Companion.asHpkePublicKey
import com.github.traderjoe95.mls.protocol.types.crypto.KemOutput
import com.github.traderjoe95.mls.protocol.types.crypto.KemOutput.Companion.asKemOutput
import com.github.traderjoe95.mls.protocol.types.crypto.Nonce
import com.github.traderjoe95.mls.protocol.types.crypto.Nonce.Companion.asNonce
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.crypto.Secret.Companion.asSecret
import com.github.traderjoe95.mls.protocol.types.crypto.Signature
import com.github.traderjoe95.mls.protocol.types.crypto.Signature.Companion.asSignature
import com.github.traderjoe95.mls.protocol.types.crypto.SignaturePrivateKey
import com.github.traderjoe95.mls.protocol.types.crypto.SignaturePrivateKey.Companion.asSignaturePrivateKey
import com.github.traderjoe95.mls.protocol.types.crypto.SignaturePublicKey
import com.github.traderjoe95.mls.protocol.types.crypto.SignaturePublicKey.Companion.asSignaturePublicKey
import com.github.traderjoe95.mls.protocol.types.framing.content.ApplicationData
import io.vertx.core.json.JsonObject

fun JsonObject.getUShort(key: String): UShort = getInteger(key).toUShort()

fun JsonObject.getUInt(key: String): UInt = getLong(key).toUInt()

fun JsonObject.getULong(key: String): ULong = getLong(key).toULong()

fun JsonObject.getCipherSuite(key: String): CipherSuite = CipherSuite(getUShort(key))!!

@OptIn(ExperimentalStdlibApi::class)
fun JsonObject.getHexBinary(key: String): ByteArray = getString(key).hexToByteArray()

@OptIn(ExperimentalStdlibApi::class)
fun JsonObject.getHexBinaryOrNull(key: String): ByteArray? = getString(key)?.hexToByteArray()

@OptIn(ExperimentalStdlibApi::class)
fun JsonObject.getHexBinary(
  key: String,
  default: ByteArray,
): ByteArray = getHexBinaryOrNull(key) ?: default

fun JsonObject.getSecret(key: String): Secret = getHexBinary(key).asSecret

fun JsonObject.getSecret(
  key: String,
  default: Secret,
): Secret = getHexBinary(key, default.bytes).asSecret

fun JsonObject.getNonce(key: String): Nonce = getHexBinary(key).asNonce

fun JsonObject.getSignaturePrivateKey(key: String): SignaturePrivateKey = getHexBinary(key).asSignaturePrivateKey

fun JsonObject.getSignaturePublicKey(key: String): SignaturePublicKey = getHexBinary(key).asSignaturePublicKey

fun JsonObject.getHpkePrivateKey(key: String): HpkePrivateKey = getHexBinary(key).asHpkePrivateKey

fun JsonObject.getHpkePublicKey(key: String): HpkePublicKey = getHexBinary(key).asHpkePublicKey

fun JsonObject.getCiphertext(key: String): Ciphertext = getHexBinary(key).asCiphertext

fun JsonObject.getKemOutput(key: String): KemOutput = getHexBinary(key).asKemOutput

fun JsonObject.getHashReference(key: String): HashReference = getHexBinary(key).asHashReference

fun JsonObject.getSignature(key: String): Signature = getHexBinary(key).asSignature

fun JsonObject.getGroupId(key: String): GroupId = getHexBinary(key).asGroupId

fun JsonObject.getApplicationData(key: String): ApplicationData = ApplicationData(getHexBinary(key))
