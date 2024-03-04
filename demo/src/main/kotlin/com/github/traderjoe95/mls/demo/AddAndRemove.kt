package com.github.traderjoe95.mls.demo

import arrow.core.Either
import arrow.core.getOrElse
import com.github.traderjoe95.mls.demo.client.Client
import com.github.traderjoe95.mls.demo.service.DeliveryService
import com.github.traderjoe95.mls.protocol.client.ActiveGroupClient
import com.github.traderjoe95.mls.protocol.types.BasicCredential
import com.github.traderjoe95.mls.protocol.types.framing.content.Add
import com.github.traderjoe95.mls.protocol.util.debug

fun <R> Either<*, R>.getOrThrow() = getOrElse { error("Unexpected error: $it") }

suspend fun main() {
  val alice = Client("Alice")
  val bob = Client("Bob")
  val charlie = Client("Charlie")

  alice.generateKeyPackages(10U)
  bob.generateKeyPackages(10U)
  charlie.generateKeyPackages(10U)

  // Alice creates the group. At this point, she is the only member
  val aliceGroup = alice.createGroup().getOrThrow()
  println("ALICE EPOCH 0 (Only Alice):")
  println("================================================================")
  println(aliceGroup.state.debug)
  println()

  // Alice adds Bob and creates a Welcome message for him to join the group and bootstrap his shared cryptographic state
  // -- In principle, this also sends a Commit message for all group members, but as Alice is the only person in the
  // -- group, it won't really go to anyone
  val bobKeyPackage = alice.getKeyPackageFor(Config.cipherSuite, "Bob")
  val addBob = aliceGroup.addMember(bobKeyPackage).getOrThrow()
  DeliveryService.sendMessageToGroup(addBob, aliceGroup.groupId).getOrThrow()

  // Process the proposal
  alice.processNextMessage().getOrThrow()

  // Alice now commits the proposal
  val addBobCommit = aliceGroup.commit().getOrThrow()
  DeliveryService.sendMessageToGroup(addBobCommit, aliceGroup.groupId).getOrThrow()

  // Process the commit, Alice now sends the Welcome to Bob
  alice.processNextMessage().getOrThrow()

  // Bob processes the Welcome and bootstraps his state
  val bobGroup = bob.processNextMessage().getOrThrow()!! as ActiveGroupClient<String>

  println("ALICE EPOCH 1 (Alice+Bob):")
  println("================================================================")
  println(aliceGroup.state.debug)
  println()

  println("BOB EPOCH 1 (Alice+Bob):")
  println("================================================================")
  println()
  println(bobGroup.state.debug)

  println()
  println("Sending messages:")

  println("Alice: ")
  alice.sendMessage(aliceGroup.groupId, "Hello, this is Alice!")
  bob.processNextMessage()
  println()

  println("Bob: ")
  bob.sendMessage(bobGroup.groupId, "Hello, this is Bob!")
  alice.processNextMessage()
  println()

  println("Alice: ")
  alice.sendMessage(aliceGroup.groupId, "How are you, Bob?")
  bob.processNextMessage()
  println()

  println("Bob: ")
  bob.sendMessage(bobGroup.groupId, "I'm fine, thanks!")
  alice.processNextMessage()
  println()

  println()
  println()

  // -- Alice and Bob have shared cryptographic state.
  // ---- For Alice, it's already the second epoch of the group she sees (1st: only Alice, 2nd: Alice+Bob)
  // 1. Bob updates the group by adding Charlie
  // 2. This sends a Commit message to all existing members of the group (i.e. Alice), changing the group state to
  //    include Charlie and establish shared cryptographic state with him
  // 3. This sends a Welcome message to Charlie which he can use to join the group and bootstrap the shared
  //    cryptographic state
  val charlieKeyPackage = bob.getKeyPackageFor(Config.cipherSuite, "Charlie")
  val addCharlieCommit = bobGroup.commit(listOf(Add(charlieKeyPackage))).getOrThrow()
  DeliveryService.sendMessageToGroup(addCharlieCommit, bobGroup.groupId).getOrThrow()

  // Alice processes the commit
  alice.processNextMessage().getOrThrow()

  // Bob processes the commit and sends the welcome message
  bob.processNextMessage().getOrThrow()

  // Charlie receives the commit
  val charlieGroup = charlie.processNextMessage().getOrThrow()!! as ActiveGroupClient<String>

  println()

  println("ALICE EPOCH 2 (Alice+Bob+Charlie):")
  println("================================================================")
  println(aliceGroup.state.debug)
  println()

  println("BOB EPOCH 2 (Alice+Bob+Charlie):")
  println("================================================================")
  println(bobGroup.state.debug)
  println()

  println("CHARLIE EPOCH 2 (Alice+Bob+Charlie):")
  println("================================================================")
  println(charlieGroup.state.debug)
  println()

  println()
  println("Sending messages:")

  println("Alice: ")
  alice.sendMessage(aliceGroup.groupId, "Hello, this is Alice!")
  print("  [Bob] ")
  bob.processNextMessage()
  print("  [Charlie] ")
  charlie.processNextMessage()

  println("Bob: ")
  bob.sendMessage(bobGroup.groupId, "Hello, this is Bob!")
  print("  [Alice] ")
  alice.processNextMessage()
  print("  [Charlie] ")
  charlie.processNextMessage()

  println("Charlie: ")
  charlie.sendMessage(charlieGroup.groupId, "How are you, Bob?")
  print("  [Alice] ")
  alice.processNextMessage()
  print("  [Bob] ")
  bob.processNextMessage()

  println("Bob: ")
  bob.sendMessage(bobGroup.groupId, "I'm fine, thanks!")
  print("  [Alice] ")
  alice.processNextMessage()
  print("  [Charlie] ")
  charlie.processNextMessage()

  println("Charlie: ")
  charlie.sendMessage(charlieGroup.groupId, "Good to hear!")
  print("  [Alice] ")
  alice.processNextMessage()
  print("  [Bob] ")
  bob.processNextMessage()

  println()
  println()

  val removeCharlie =
    charlieGroup.removeMember(
      charlieGroup.members.indexOfFirst {
        "Charlie" == (it.credential as BasicCredential).identity.decodeToString()
      }.toUInt(),
    ).getOrThrow()
  DeliveryService.sendMessageToGroup(removeCharlie, charlieGroup.groupId).getOrThrow()

  alice.processNextMessage().getOrThrow()
  bob.processNextMessage().getOrThrow()
  charlie.processNextMessage().getOrThrow()

  val removeCharlieCommit = aliceGroup.commit().getOrThrow()
  DeliveryService.sendMessageToGroup(removeCharlieCommit, aliceGroup.groupId).getOrThrow()

  alice.processNextMessage().getOrThrow()
  bob.processNextMessage().getOrThrow()

  try {
    charlie.processNextMessage().getOrThrow()
  } catch (e: Throwable) {
    println("Charlie couldn't process the commit: $e")
  }

  println("ALICE EPOCH 3 (Alice+Bob):")
  println("================================================================")
  println(aliceGroup.state.debug)
  println()

  println("BOB EPOCH 3 (Alice+Bob):")
  println("================================================================")
  println()
  println(bobGroup.state.debug)

  println("Alice: ")
  alice.sendMessage(aliceGroup.groupId, "Hello, this is Alice!")
  print("  [Bob] ")
  bob.processNextMessage()
  try {
    print("  [Charlie] ")
    charlie.processNextMessage()
  } catch (t: Throwable) {
    println("Can't receive the message: $t")
  }

  println("Bob: ")
  bob.sendMessage(bobGroup.groupId, "Hello, this is Bob!")
  print("  [Alice] ")
  alice.processNextMessage()
  try {
    print("  [Charlie] ")
    charlie.processNextMessage()
  } catch (t: Throwable) {
    println("Can't receive the message: $t")
  }

  println("Charlie:")
  charlie.sendMessage(charlieGroup.groupId, "How are you, Bob?")
  // Alice and Bob should still be able to read the message, as they still hold the group state of some past epochs
  // to account for reordered or delayed messages
  try {
    print("  [Alice] ")
    alice.processNextMessage()
  } catch (t: Throwable) {
    println("Can't receive the message: $t")
  }
  try {
    print("  [Bob] ")
    bob.processNextMessage()
  } catch (t: Throwable) {
    println("Can't receive the message: $t")
  }

  println("Bob: ")
  bob.sendMessage(bobGroup.groupId, "I'm fine, thanks!")
  print("  [Alice] ")
  alice.processNextMessage()
  try {
    print("  [Charlie] ")
    charlie.processNextMessage()
  } catch (t: Throwable) {
    println("Can't receive the message: $t")
  }

  println("Charlie: ")
  charlie.sendMessage(charlieGroup.groupId, "Good to hear!")
  // Alice and Bob should still be able to read the message, as they still hold the group state of some past epochs
  // to account for reordered or delayed messages
  try {
    print("  [Alice] ")
    alice.processNextMessage()
  } catch (t: Throwable) {
    println("Can't receive the message: $t")
  }
  try {
    print("  [Bob] ")
    bob.processNextMessage()
  } catch (t: Throwable) {
    println("Can't receive the message: $t")
  }
}
