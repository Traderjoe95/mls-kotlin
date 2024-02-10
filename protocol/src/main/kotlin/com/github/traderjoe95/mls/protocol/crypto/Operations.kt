package com.github.traderjoe95.mls.protocol.crypto

import arrow.core.raise.Raise
import com.github.traderjoe95.mls.codec.error.EncoderError
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite.Companion.zeroesNh
import com.github.traderjoe95.mls.protocol.types.crypto.PreSharedKeyId
import com.github.traderjoe95.mls.protocol.types.crypto.PskLabel
import com.github.traderjoe95.mls.protocol.types.crypto.Secret

context(ICipherSuite, Raise<EncoderError>)
fun List<Pair<PreSharedKeyId, Secret>>.calculatePskSecret(): Secret {
  var pskSecret = zeroesNh
  var pskInput: Secret

  for (i in indices) {
    val (pskId, psk) = this[i]

    pskInput =
      expandWithLabel(
        extract(zeroesNh.key, psk),
        "derivedPsk",
        PskLabel.T.encode(PskLabel(pskId, i, size)),
        hashLen,
      )

    pskSecret = extract(pskInput.key, pskSecret)
  }

  return pskSecret
}
