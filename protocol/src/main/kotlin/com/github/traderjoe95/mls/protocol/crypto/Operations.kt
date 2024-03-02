package com.github.traderjoe95.mls.protocol.crypto

import com.github.traderjoe95.mls.protocol.crypto.CipherSuite.Companion.zeroesNh
import com.github.traderjoe95.mls.protocol.psk.PreSharedKeyId
import com.github.traderjoe95.mls.protocol.psk.PskLabel
import com.github.traderjoe95.mls.protocol.psk.PskLabel.Companion.encodeUnsafe
import com.github.traderjoe95.mls.protocol.types.crypto.Ciphertext
import com.github.traderjoe95.mls.protocol.types.crypto.Nonce
import com.github.traderjoe95.mls.protocol.types.crypto.Secret

fun calculatePskSecret(
  cipherSuite: ICipherSuite,
  psks: List<Pair<PreSharedKeyId, Secret>>,
): Secret =
  with(cipherSuite) {
    psks.foldIndexed(this.zeroesNh) { idx, pskSecret, (pskId, psk) ->
      this.updatePskSecret(pskSecret, pskId, psk, idx, psks.size)
    }
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

fun getSenderDataNonceAndKey(
  cipherSuite: ICipherSuite,
  senderDataSecret: Secret,
  ciphertext: Ciphertext,
): Pair<Nonce, Secret> =
  with(cipherSuite) {
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
  }
