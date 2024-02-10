package de.traderjoe.ulid.suspending

import de.traderjoe.ulid.ULID

suspend fun ULID.Companion.new(): ULID = next()

suspend fun ULID.Companion.newString() = new().toString()

suspend fun ULID.Companion.newBinary() = new().toBytes()
