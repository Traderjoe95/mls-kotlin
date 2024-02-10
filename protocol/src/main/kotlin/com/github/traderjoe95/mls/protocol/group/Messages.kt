package com.github.traderjoe95.mls.protocol.group

import com.github.traderjoe95.mls.protocol.types.framing.Sender
import com.github.traderjoe95.mls.protocol.types.framing.content.Content
import com.github.traderjoe95.mls.protocol.types.framing.content.FramedContent

fun <C : Content> GroupState.createFramedContent(
  content: C,
  authenticatedData: ByteArray = byteArrayOf(),
): FramedContent<C> =
  FramedContent(
    groupId,
    currentEpoch,
    Sender.member(ownLeafIndex),
    authenticatedData,
    content,
  )