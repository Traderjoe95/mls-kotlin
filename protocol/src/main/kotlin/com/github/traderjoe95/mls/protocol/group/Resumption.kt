package com.github.traderjoe95.mls.protocol.group

import arrow.core.Tuple5
import arrow.core.raise.Raise
import com.github.traderjoe95.mls.protocol.app.ApplicationCtx
import com.github.traderjoe95.mls.protocol.crypto.CipherSuite
import com.github.traderjoe95.mls.protocol.error.BranchError
import com.github.traderjoe95.mls.protocol.error.ReInitError
import com.github.traderjoe95.mls.protocol.types.GroupContextExtensions
import com.github.traderjoe95.mls.protocol.types.crypto.ResumptionPskId
import com.github.traderjoe95.mls.protocol.types.framing.MlsMessage
import com.github.traderjoe95.mls.protocol.types.framing.content.Add
import com.github.traderjoe95.mls.protocol.types.framing.content.PreSharedKey
import com.github.traderjoe95.mls.protocol.types.framing.content.ReInit
import com.github.traderjoe95.mls.protocol.types.framing.enums.ProtocolVersion
import com.github.traderjoe95.mls.protocol.types.framing.message.GroupInfo
import com.github.traderjoe95.mls.protocol.types.framing.message.PrivateMessage
import com.github.traderjoe95.mls.protocol.types.framing.message.Welcome
import de.traderjoe.ulid.ULID
import de.traderjoe.ulid.suspending.new

context(Raise<ReInitError>, ApplicationCtx<Identity>)
suspend fun <Identity : Any> GroupState.reInitGroup(
  groupId: ULID? = null,
  protocolVersion: ProtocolVersion = this.settings.protocolVersion,
  cipherSuite: CipherSuite = this.cipherSuite,
  extensions: GroupContextExtensions = this.extensions,
  authenticatedData: ByteArray = byteArrayOf(),
  public: Boolean = false,
  keepPastEpochs: UInt = 5U,
): Tuple5<GroupState, MlsMessage<PrivateMessage>, GroupInfo, MlsMessage<Welcome>, GroupState> {
  val newGroupId = groupId ?: ULID.new()

  val (oldGroupAfterCommit, commitMsg, _, _) =
    prepareCommit(
      listOf(ReInit(newGroupId, protocolVersion, cipherSuite, extensions)),
      authenticatedData = authenticatedData,
    )

  val newGroupInitial =
    newGroup(
      cipherSuite,
      *extensions.toTypedArray(),
      protocolVersion = protocolVersion,
      groupId = newGroupId,
      public = public,
      keepPastEpochs = keepPastEpochs,
    )

  val keyPackages =
    getKeyPackages(
      protocolVersion,
      cipherSuite,
      authenticateCredentials(tree.leaves.filterNotNull().map { it.node }).bindAll(),
    ).values.bindAll()

  val (newGroupAfterCommit, _, newGroupInfo, welcome) =
    newGroupInitial.prepareCommit(
      keyPackages.map(::Add) + PreSharedKey(ResumptionPskId.reInit(oldGroupAfterCommit, cipherSuite)),
      inReInit = true,
    )

  return Tuple5(oldGroupAfterCommit, commitMsg, newGroupInfo, welcome!!, newGroupAfterCommit)
}

context(Raise<BranchError>, ApplicationCtx<Identity>)
suspend fun <Identity : Any> GroupState.branchGroup(
  leafIndices: List<UInt>,
  groupId: ULID? = null,
  extensions: GroupContextExtensions = this.extensions,
  public: Boolean = false,
  keepPastEpochs: UInt = 5U,
): Triple<GroupState, GroupInfo, MlsMessage<Welcome>> {
  val newGroupId = groupId ?: ULID.new()

  val newGroupInitial =
    newGroup(
      cipherSuite,
      *extensions.toTypedArray(),
      protocolVersion = settings.protocolVersion,
      groupId = newGroupId,
      public = public,
      keepPastEpochs = keepPastEpochs,
    )

  val leafNodes =
    tree.leafIndices
      .filter { it / 2U in leafIndices }
      .map { it to tree[it]?.asLeaf }
      .partition { it.second != null }
      .let { (nonBlank, blank) ->
        if (blank.isNotEmpty()) raise(BranchError.BlankLeavesIncluded(blank.map { it.first }))

        nonBlank.map { it.second!! }
      }

  val keyPackages =
    getKeyPackages(
      settings.protocolVersion,
      cipherSuite,
      authenticateCredentials(leafNodes.map { it.node }).bindAll(),
    ).values.bindAll()

  val (newGroupAfterCommit, _, newGroupInfo, welcome) =
    newGroupInitial.prepareCommit(
      keyPackages.map(::Add) + PreSharedKey(ResumptionPskId.branch(this)),
      inBranch = true,
    )

  return Triple(newGroupAfterCommit, newGroupInfo, welcome!!)
}
