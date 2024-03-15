package com.github.traderjoe95.mls.interop.store

import com.github.traderjoe95.mls.interop.invalidArgument
import com.github.traderjoe95.mls.protocol.group.GroupState
import com.github.traderjoe95.mls.protocol.message.KeyPackage
import com.github.traderjoe95.mls.protocol.message.MessageOptions
import com.github.traderjoe95.mls.protocol.types.BasicCredential
import com.github.traderjoe95.mls.protocol.types.crypto.SignatureKeyPair
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

class StateStore {
  private val stateStoreMutex = Mutex()

  private var idCounter: Int = 0
  private val states: MutableMap<Int, StoredState> = mutableMapOf()
  private val transactions: MutableMap<Int, Transaction> = mutableMapOf()
  private val reInit: MutableMap<Int, PendingReInit> = mutableMapOf()
  private val signers: MutableMap<Int, ExternalSigner> = mutableMapOf()

  suspend fun storeState(
    groupState: GroupState,
    handshakeOptions: MessageOptions,
  ): Int =
    stateStoreMutex.withLock {
      idCounter++.also {
        states[it] = StoredState(it, groupState, handshakeOptions)
      }
    }

  suspend fun storeTransaction(keyPackage: KeyPackage.Private): Int =
    stateStoreMutex.withLock {
      idCounter++.also {
        transactions[it] = Transaction(keyPackage)
      }
    }

  suspend fun storeReInit(
    suspendedGroup: GroupState.Suspended,
    keyPackage: KeyPackage.Private,
    handshakeOptions: MessageOptions,
  ): Int =
    stateStoreMutex.withLock {
      idCounter++.also {
        reInit[it] = PendingReInit(it, suspendedGroup, keyPackage, handshakeOptions)
      }
    }

  suspend fun storeSigner(
    keyPair: SignatureKeyPair,
    credential: BasicCredential,
  ): Int =
    stateStoreMutex.withLock {
      idCounter++.also {
        signers[it] = ExternalSigner(keyPair, credential)
      }
    }

  suspend fun removeState(id: Int) =
    stateStoreMutex.withLock {
      states.remove(id) ?: invalidArgument("state_id $id is unknown")
    }

  fun getTransactionOrNull(id: Int): Transaction? = transactions[id]

  fun getTransaction(id: Int): Transaction = getTransactionOrNull(id) ?: invalidArgument("transaction_id $id is unknown")

  fun getStateOrNull(id: Int): StoredState? = states[id]

  fun getState(id: Int): StoredState = getStateOrNull(id) ?: invalidArgument("state_id $id is unknown")

  fun getReInitOrNull(id: Int): PendingReInit? = reInit[id]

  fun getReInit(id: Int): PendingReInit = getReInitOrNull(id) ?: invalidArgument("reinit_id $id is unknown")

  fun getSignerOrNull(id: Int): ExternalSigner? = signers[id]

  fun getSigner(id: Int): ExternalSigner = getSignerOrNull(id) ?: invalidArgument("signer_id $id is unknown")
}
