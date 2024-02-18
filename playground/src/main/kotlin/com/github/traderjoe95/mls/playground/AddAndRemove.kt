package com.github.traderjoe95.mls.playground

import arrow.core.Either
import arrow.core.getOrElse
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
  val aliceGroup1 = alice.createGroup().getOrThrow()
  println("ALICE EPOCH 0 (Only Alice):")
  println("================================================================")
  println(aliceGroup1.state.debug)
  println()

  // Alice adds Bob and creates a Welcome message for him to join the group and bootstrap his shared cryptographic state
  // -- In principle, this also sends a Commit message for all group members, but as Alice is the only person in the
  // -- group, it won't really go to anyone
  val aliceGroup2 = aliceGroup1.addMember("Bob").getOrThrow()

  println("ALICE EPOCH 1 (Alice+Bob):")
  println("================================================================")
  println(aliceGroup2.state.debug)
  println()

  // Bob processes the Welcome and bootstraps his state
  val bobGroup1 = bob.processNextMessage()!!

  println("BOB EPOCH 1 (Alice+Bob):")
  println("================================================================")
  println()
  println(bobGroup1.state.debug)

  println()
  println("Sending messages:")

  println("Alice: ")
  aliceGroup2.sendPrivateApplicationMessage("Hello, this is Alice!")
  bob.processNextMessage()
  println()

  println("Bob (using public message): ")
  bobGroup1.sendPublicApplicationMessage("Hello, this is Bob!")
  alice.processNextMessage()
  println()

  println("Alice (using public message): ")
  aliceGroup2.sendPublicApplicationMessage("How are you, Bob?")
  bob.processNextMessage()
  println()

  println("Bob: ")
  bobGroup1.sendPrivateApplicationMessage("I'm fine, thanks!")
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
  val bobGroup2 = bobGroup1.addMember("Charlie").getOrThrow()
  val aliceGroup3 = alice.processNextMessage()!! // <-- Alice processes the Commit message and receives a new group state
  val charlieGroup1 = charlie.processNextMessage()!! // <-- Charlie processes the Welcome message and receives the shared group state

  println()

  println("ALICE EPOCH 2 (Alice+Bob+Charlie):")
  println("================================================================")
  println(aliceGroup3.state.debug)
  println()

  println("BOB EPOCH 2 (Alice+Bob+Charlie):")
  println("================================================================")
  println(bobGroup2.state.debug)
  println()

  println("CHARLIE EPOCH 2 (Alice+Bob+Charlie):")
  println("================================================================")
  println(charlieGroup1.state.debug)
  println()

  println()
  println("Sending messages:")

  println("Alice: ")
  aliceGroup3.sendPrivateApplicationMessage("Hello, this is Alice!")
  print("  [Bob] ")
  bob.processNextMessage()
  print("  [Charlie] ")
  charlie.processNextMessage()

  println("Bob (using public message): ")
  bobGroup2.sendPublicApplicationMessage("Hello, this is Bob!")
  print("  [Alice] ")
  alice.processNextMessage()
  print("  [Charlie] ")
  charlie.processNextMessage()

  println("Charlie (using public message): ")
  charlieGroup1.sendPublicApplicationMessage("How are you, Bob?")
  print("  [Alice] ")
  alice.processNextMessage()
  print("  [Bob] ")
  bob.processNextMessage()

  println("Bob: ")
  bobGroup2.sendPrivateApplicationMessage("I'm fine, thanks!")
  print("  [Alice] ")
  alice.processNextMessage()
  print("  [Charlie] ")
  charlie.processNextMessage()

  println("Charlie: ")
  charlieGroup1.sendPrivateApplicationMessage("Good to hear!")
  print("  [Alice] ")
  alice.processNextMessage()
  print("  [Bob] ")
  bob.processNextMessage()

  println()
  println()

  val aliceGroup4 = aliceGroup3.removeMember("Charlie").getOrThrow()
  val bobGroup3 = bob.processNextMessage()!! // Bob should be able to process the Commit removing Charlie

  try {
    charlie.processNextMessage()
  } catch (e: Throwable) {
    println("Charlie couldn't process the commit: $e")
  }

  println("ALICE EPOCH 3 (Alice+Bob):")
  println("================================================================")
  println(aliceGroup4.state.debug)
  println()

  println("BOB EPOCH 3 (Alice+Bob):")
  println("================================================================")
  println()
  println(bobGroup3.state.debug)

  println("Alice: ")
  aliceGroup4.sendPrivateApplicationMessage("Hello, this is Alice!")
  print("  [Bob] ")
  bob.processNextMessage()
  try {
    print("  [Charlie] ")
    charlie.processNextMessage()
  } catch (t: Throwable) {
    println("Can't receive the message: $t")
  }

  println("Bob (using public message): ")
  bobGroup3.sendPublicApplicationMessage("Hello, this is Bob!")
  print("  [Alice] ")
  alice.processNextMessage()
  try {
    print("  [Charlie] ")
    charlie.processNextMessage()
  } catch (t: Throwable) {
    println("Can't receive the message: $t")
  }

  println("Charlie (using public message):")
  charlieGroup1.sendPublicApplicationMessage("How are you, Bob?")
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
  bobGroup3.sendPrivateApplicationMessage("I'm fine, thanks!")
  print("  [Alice] ")
  alice.processNextMessage()
  try {
    print("  [Charlie] ")
    charlie.processNextMessage()
  } catch (t: Throwable) {
    println("Can't receive the message: $t")
  }

  println("Charlie: ")
  charlieGroup1.sendPrivateApplicationMessage("Good to hear!")
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
