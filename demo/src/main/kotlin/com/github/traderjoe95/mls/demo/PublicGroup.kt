package com.github.traderjoe95.mls.demo

import com.github.traderjoe95.mls.demo.client.Client
import com.github.traderjoe95.mls.demo.util.makePublic
import com.github.traderjoe95.mls.protocol.util.debug

suspend fun main() {
  val alice = Client("Alice")
  val bob = Client("Bob")
  val charlie = Client("Charlie")

  alice.generateKeyPackages(10U)
  bob.generateKeyPackages(10U)
  charlie.generateKeyPackages(10U)

  // Alice creates the group. At this point, she is the only member
  val aliceGroup = alice.createGroup().getOrThrow()
  aliceGroup.makePublic()
  println("ALICE EPOCH 0 (Only Alice):")
  println("================================================================")
  println(aliceGroup.state.debug)
  println()

  val bobGroup = bob.joinPublicGroup(aliceGroup.state.groupId).getOrThrow()

  alice.processNextMessage().getOrThrow()

  println("ALICE EPOCH 1 (Alice+Bob):")
  println("================================================================")
  println(aliceGroup.state.debug)
  println()

  println("Bob EPOCH 1 (Alice+Bob):")
  println("================================================================")
  println(bobGroup.state.debug)
  println()

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

  bobGroup.makePublic()

  val charlieGroup = charlie.joinPublicGroup(bobGroup.state.groupId).getOrThrow()

  alice.processNextMessage().getOrThrow()
  bob.processNextMessage().getOrThrow()

  println("ALICE EPOCH 2 (Alice+Charlie):")
  println("================================================================")
  println(aliceGroup.state.debug)
  println()

  println("Bob EPOCH 2 (Alice+Bob+Charlie):")
  println("================================================================")
  println(bobGroup.state.debug)
  println()

  println("Charlie EPOCH 2 (Alice+Bob+Charlie):")
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
}
