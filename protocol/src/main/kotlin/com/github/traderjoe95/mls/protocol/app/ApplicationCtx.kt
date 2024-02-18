package com.github.traderjoe95.mls.protocol.app

import arrow.core.Tuple4
import arrow.core.raise.Raise
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.error.BranchJoinError
import com.github.traderjoe95.mls.protocol.error.ExternalPskError
import com.github.traderjoe95.mls.protocol.error.ReInitJoinError
import com.github.traderjoe95.mls.protocol.error.ResumptionPskError
import com.github.traderjoe95.mls.protocol.group.resumption.BranchEvidence
import com.github.traderjoe95.mls.protocol.group.resumption.ReInitEvidence
import com.github.traderjoe95.mls.protocol.service.AuthenticationService
import com.github.traderjoe95.mls.protocol.service.DeliveryService
import com.github.traderjoe95.mls.protocol.types.crypto.HpkeKeyPair
import com.github.traderjoe95.mls.protocol.types.crypto.Secret
import com.github.traderjoe95.mls.protocol.types.crypto.SigningKey
import com.github.traderjoe95.mls.protocol.types.framing.message.KeyPackage
import de.traderjoe.ulid.ULID

interface ApplicationCtx<Identity : Any> : AuthenticationService<Identity>, DeliveryService<Identity> {
  fun newKeyPackage(cipherSuite: CipherSuite): Tuple4<KeyPackage, HpkeKeyPair, HpkeKeyPair, SigningKey>

  fun getKeyPackage(ref: KeyPackage.Ref): Tuple4<KeyPackage, HpkeKeyPair, HpkeKeyPair, SigningKey>?

  context(Raise<ExternalPskError>)
  suspend fun getExternalPsk(id: ByteArray): Secret

  context(Raise<ResumptionPskError>)
  suspend fun getResumptionPsk(
    groupId: ULID,
    epoch: ULong,
  ): Secret

  fun groupIdExists(id: ULID): Boolean

  fun suspendGroup(groupId: ULID)

  context(Raise<ReInitJoinError>)
  fun getReInitEvidence(groupId: ULID): ReInitEvidence

  context(Raise<BranchJoinError>)
  fun getBranchEvidence(groupId: ULID): BranchEvidence
}
