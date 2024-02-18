package com.github.traderjoe95.mls.protocol.tree

import arrow.core.raise.nullable
import com.github.traderjoe95.mls.protocol.types.crypto.HpkeKeyPair
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePrivateKey
import com.github.traderjoe95.mls.protocol.types.crypto.HpkePublicKey

internal class TreePrivateKeyStore(
  private val privateKeys: MutableMap<Int, HpkePrivateKey>,
) {
  fun getPrivateKeyFor(publicKey: HpkePublicKey): HpkePrivateKey? = privateKeys[publicKey.key.contentHashCode()]

  fun getKeyPairFor(publicKey: HpkePublicKey): HpkeKeyPair? = nullable { HpkeKeyPair(getPrivateKeyFor(publicKey).bind() to publicKey) }

  fun storePrivateKey(hpkeKeyPair: HpkeKeyPair) = storePrivateKey(hpkeKeyPair.public, hpkeKeyPair.private)

  fun storePrivateKey(
    publicKey: HpkePublicKey,
    privateKey: HpkePrivateKey,
  ) {
    privateKeys[publicKey.key.contentHashCode()] = privateKey
  }

  fun copy(): TreePrivateKeyStore = TreePrivateKeyStore(privateKeys.mapValues { it.value.move() }.toMutableMap())

  fun move(): TreePrivateKeyStore = TreePrivateKeyStore(privateKeys.mapValues { it.value.copy() }.toMutableMap())

  fun wipe() {
    privateKeys.values.forEach(HpkePrivateKey::wipe)
  }

  fun wipeUnused(usedPublicKeys: List<HpkePublicKey>) {
    val usedHashCodes = usedPublicKeys.map { it.key.contentHashCode() }.toSet()

    privateKeys.keys
      .filterNot(usedHashCodes::contains)
      .forEach { privateKeys.remove(it)?.wipe() }
  }

  companion object {
    fun init(keyPair: HpkeKeyPair): TreePrivateKeyStore = init(keyPair.public, keyPair.private)

    fun init(
      publicKey: HpkePublicKey,
      privateKey: HpkePrivateKey,
    ): TreePrivateKeyStore = TreePrivateKeyStore(mutableMapOf(publicKey.key.contentHashCode() to privateKey))
  }
}
