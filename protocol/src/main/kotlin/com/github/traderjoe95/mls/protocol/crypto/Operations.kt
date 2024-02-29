package com.github.traderjoe95.mls.protocol.crypto

import com.github.traderjoe95.mls.protocol.crypto.CipherSuite.Companion.zeroesNh
import com.github.traderjoe95.mls.protocol.psk.PreSharedKeyId
import com.github.traderjoe95.mls.protocol.psk.PskLabel
import com.github.traderjoe95.mls.protocol.psk.PskLabel.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.types.crypto.Ciphertext
import com.github.traderjoe95.mls.protocol.types.crypto.Nonce
import com.github.traderjoe95.mls.protocol.types.crypto.Secret

context(ICipherSuite)
fun List<Pair<PreSharedKeyId, Secret>>.calculatePskSecret(): Secret =
  foldIndexed(zeroesNh) { idx, pskSecret, (pskId, psk) ->
    updatePskSecret(pskSecret, pskId, psk, idx, size)
  }

internal fun ICipherSuite.updatePskSecret(
  pskSecret: Secret,
  pskId: PreSharedKeyId,
  psk: Secret,
  index: Int,
  count: Int,
): Secret =
  extract(
    expandWithLabel(
      extract(zeroesNh.bytes, psk),
      "derived psk",
      PskLabel(pskId, index, count).encodeUnsafe(),
      hashLen,
    ).bytes,
    pskSecret,
  )

fun ICipherSuite.getSenderDataNonceAndKey(
  senderDataSecret: Secret,
  ciphertext: Ciphertext,
): Pair<Nonce, Secret> =
  ciphertext.bytes.sliceArray(0..<minOf(ciphertext.size, hashLen.toInt())).let { ciphertextSample ->
    expandWithLabel(
      senderDataSecret,
      "nonce",
      ciphertextSample,
      nonceLen,
    ).asNonce to
      expandWithLabel(
        senderDataSecret,
        "key",
        ciphertextSample,
        keyLen,
      )
  }
