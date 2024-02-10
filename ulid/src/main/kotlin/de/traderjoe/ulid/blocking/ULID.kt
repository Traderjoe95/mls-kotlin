package de.traderjoe.ulid.blocking

import de.traderjoe.ulid.ULID
import kotlinx.coroutines.runBlocking

fun ULID.Companion.new(): ULID = runBlocking { next() }

fun ULID.Companion.newString() = new().toString()

fun ULID.Companion.newBinary() = new().toBytes()
