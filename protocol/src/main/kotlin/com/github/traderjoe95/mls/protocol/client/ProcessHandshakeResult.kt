package com.github.traderjoe95.mls.protocol.client

import com.github.traderjoe95.mls.protocol.group.WelcomeMessages

sealed interface ProcessHandshakeResult<out Identity : Any> {
  data object ProposalReceived : ProcessHandshakeResult<Nothing>

  data object CommitProcessed : ProcessHandshakeResult<Nothing>

  data class CommitProcessedWithNewMembers(val welcomeMessages: WelcomeMessages) : ProcessHandshakeResult<Nothing>

  data class ReInitProcessed<Identity : Any>(val suspendedClient: SuspendedGroupClient<Identity>) :
    ProcessHandshakeResult<Identity>
}
