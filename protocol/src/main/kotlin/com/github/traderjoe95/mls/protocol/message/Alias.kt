package com.github.traderjoe95.mls.protocol.message

import com.github.traderjoe95.mls.protocol.types.framing.content.ApplicationData
import com.github.traderjoe95.mls.protocol.types.framing.content.AuthenticatedContent
import com.github.traderjoe95.mls.protocol.types.framing.content.Commit
import com.github.traderjoe95.mls.protocol.types.framing.content.Content
import com.github.traderjoe95.mls.protocol.types.framing.content.Proposal

typealias HandshakeContent = Content.Handshake<*>
typealias AuthHandshakeContent = AuthenticatedContent<HandshakeContent>

typealias HandshakeMessage<Err> = GroupMessage<HandshakeContent, Err>
typealias CommitMessage<Err> = GroupMessage<Commit, Err>
typealias ProposalMessage<Err> = GroupMessage<Proposal, Err>
typealias ApplicationMessage = PrivateMessage<ApplicationData>

typealias MlsHandshakeMessage<Err> = MlsMessage<HandshakeMessage<Err>>
typealias MlsProposalMessage<Err> = MlsMessage<ProposalMessage<Err>>
typealias MlsCommitMessage<Err> = MlsMessage<CommitMessage<Err>>
