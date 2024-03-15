package com.github.traderjoe95.mls.interop.store

import com.github.traderjoe95.mls.interop.HoldsExternalPsks
import com.github.traderjoe95.mls.protocol.message.KeyPackage
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.util.hex

data class Transaction(
  val keyPackage: KeyPackage.Private,
  val externalPsks: MutableMap<String, Secret> = mutableMapOf(),
) : HoldsExternalPsks {
  override fun addExternalPsk(
    id: ByteArray,
    psk: Secret,
  ) {
    externalPsks[id.hex] = psk
  }

  override fun getExternalPask(id: ByteArray): Secret? = externalPsks[id.hex]
}
