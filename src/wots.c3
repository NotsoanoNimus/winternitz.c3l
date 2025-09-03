// Copyright (c) 2025 Zack Puhl (NotsoanoNimus) <github@xmit.xyz>. All rights reserved.
// Use of this source code is governed by the MIT license,
// a copy of which can be found in the LICENSE file.
//
// A C3 implementation of Winternitz One-Time Signatures (NOT the "plus" variant used in XMSS).
//
<*
 @require @in(W, 4, 16, 256, 65536, 4294967296) : `The Winternitz parameter must be 4, 16, 256, 65536, or 4294967296 (to log2: 2, 4, 8, 16, 32)`
 @require types::is_int($typeof(N)) &&& N > 0 : `N must be a positive integer`
 @require (N * 8) % math::@intlog2(W) == 0 : `The bit-size of N (8N) must be an even multiple of log2(W); usually this is a hash digest's length`
*>
module winternitz_internal { W, N } @private;

import std::math, std::bits, std::io;

const usz LEN = N * (LEN_SIGNATURE + LEN_CHECKSUM);
const usz LEN_SIGNATURE @local = (int)$$ceil((8.0f * N) / math::@intlog2(W));   // how many times log2(W) fits into N (digest size) to bits
const usz LEN_CHECKSUM @local = (math::@intlog2(LEN_SIGNATURE * (W - 1)) / math::@intlog2(W)) + 1;

const usz UNIT_BITSIZE @local = math::@intlog2(W);   // each sequence of log2(W) bits from the digest determines the hash chain lengths
const usz UNIT_BYTESIZE @local = UNIT_BITSIZE / 8 + (!!(UNIT_BITSIZE % 8) ??? 1 : 0);   // how many bytes are in one slice of the digest
const uint128 BITMASK @local = W - 1;   // W = 4 -> 0b11, W = 16 -> 0b1111, W = 256 -> 0b11111111, ...

// -----------------------------------------------------------
// N = 32, W = 4,     LEN_S = 128, LEN_C = 5, LEN = 133
// N = 64, W = 4,     LEN_S = 256, LEN_C = 5, LEN = 261
// ---
// N = 32, W = 16,    LEN_S = 64,  LEN_C = 3, LEN = 67
// N = 64, W = 16,    LEN_S = 128, LEN_C = 3, LEN = 131
// ---
// N = 32, W = 256,   LEN_S = 32,  LEN_C = 2, LEN = 34
// N = 64, W = 256,   LEN_S = 64,  LEN_C = 2, LEN = 66
// ---
// N = 32, W = 65536, LEN_S = 16,  LEN_C = 2, LEN = 18
// N = 64, W = 65536, LEN_S = 32,  LEN_C = 2, LEN = 34
// ---
// (this is absurd ha)
// N = 32, W = 4294967296, LEN_S = 8,  LEN_C = 2, LEN = 10
// N = 64, W = 4294967296, LEN_S = 16, LEN_C = 2, LEN = 18
// -----------------------------------------------------------

alias DigestFn = fn char[N] (char[]);

struct Result (Printable)
{
	char[LEN] public_key;
	char[LEN] signature;
}

fn usz? Result.to_format(&self, Formatter* f) @dynamic
{
	usz len;
	len += f.print("{\n\t--> public_key: ")!;
	foreach (c : self.public_key) len += f.printf("%02x", c)!;
	len += f.print(",\n\t--> signature: ")!;
	foreach (c : self.signature) len += f.printf("%02x", c)!;
	return len + f.print(",\n}");
}

macro bool @in(#v, ...) @const @local
{
	$foreach $c : { $vasplat }:
		$if #v == $c: return true; $endif
	$endforeach
	return false;
}

<*
 @param [in] x
*>
macro value_from(usz bit_index, char[] x) @local
{
	uint128 current_value;
	$for var $byte = UNIT_BYTESIZE; $byte > 0; --$byte:
		current_value |= (uint128)(x[bit_index / 8 + ($byte - 1)]) << ((UNIT_BYTESIZE - $byte) * 8);
	$endfor
	$if UNIT_BITSIZE < 8: current_value >>= (8 - UNIT_BITSIZE) - (bit_index % 8); $endif
	current_value &= BITMASK;
	return current_value;
}

macro @as_bytes(#x) @local => ((char*)&#x)[:UNIT_BYTESIZE];

<*
 @require digest.len == N
*>
fn bool verify_result(char[] digest, Result r, DigestFn h) => verify(digest, r.signature[..], r.public_key[..], h);

<*
 @require digest.len == N
 @require signature.len == LEN
 @require public_key.len == LEN
*>
fn bool verify(char[] digest, char[] signature, char[] public_key, DigestFn h)
{
	uint128 checksum;
	char[N] working_digest @noinit;

	for (usz n = 0, usz bit_index = 0; bit_index < N * 8; ++n, bit_index += UNIT_BITSIZE)
	{
		uint128 current_value = value_from(bit_index, digest);

		checksum += (uint128)W - 1ull - current_value;

		working_digest[..] = (&signature[n * N])[:N];
		for (usz i = (usz)current_value; i < W; ++i) working_digest[..] = h(working_digest[..])[..];

		if (working_digest[..] != (&public_key[n * N])[:N]) return false;
	}

	// Now parse the checksum.
	for (usz i = 1; i <= LEN_CHECKSUM; ++i)
	{
		uint128 current_value = (checksum >> ((LEN_CHECKSUM - i) * UNIT_BITSIZE)) & BITMASK;

		working_digest[..] = (&signature[(LEN_SIGNATURE + i - 1) * N])[:N];
		for (usz j = (usz)current_value; j < W; ++j) working_digest[..] = h(working_digest[..])[..];

		if (working_digest[..] != (&public_key[(LEN_SIGNATURE + i - 1) * N])[:N]) return false;
	}

	return true;
}

<*
 @require private_key.len == LEN : "The private key have at least 16 bytes to hash per each Winternitz block"
 @require digest.len == N
*>
fn Result sign(char[] digest, char[] private_key, DigestFn h)
{
	char[LEN] public_key;
	char[LEN] signature;
	uint128 checksum;

	char[UNIT_BYTESIZE] reversed @noinit;
	char[N] working_digest @noinit;

	for (usz n = 0, usz bit_index = 0; bit_index < N * 8; ++n, bit_index += UNIT_BITSIZE)
	{
		uint128 current_value = value_from(bit_index, digest);
		assert(current_value < W);

		checksum += (uint128)W - 1ull - current_value;   // collect the checksum value

		// now, apply the hash `current_value` times over the slice of the private key at this index
		// -- first hash is always of the private key slice at the current index
		working_digest[..] = h(private_key[(n * N):N])[..];
		// -- subsequent hashes are of the seed hash
		usz i = 1;
		for (; i < current_value; ++i) working_digest[..] = h(working_digest[..])[..];
		// Store the computed signature digest.
		(&signature[n * N])[:N] = working_digest[..];

		// Keep going up until W to get the public key digest.
		for (; i < W; ++i) working_digest[..] = h(working_digest[..])[..];
		(&public_key[n * N])[:N] = working_digest[..];
	}

	// Now parse the checksum.
	for (usz i = 1; i <= LEN_CHECKSUM; ++i)
	{
		uint128 current_value = (checksum >> ((LEN_CHECKSUM - i) * UNIT_BITSIZE)) & BITMASK;

		working_digest[..] = h(private_key[((LEN_SIGNATURE + i - 1) * N):N])[..];

		usz j = 1;
		for (; j < current_value; ++j) working_digest[..] = h(working_digest[..])[..];
		(&signature[(LEN_SIGNATURE + i - 1) * N])[:N] = working_digest[..];

		for (; j < W; ++j) working_digest[..] = h(working_digest[..])[..];
		(&public_key[(LEN_SIGNATURE + i - 1) * N])[:N] = working_digest[..];
	}

	return { public_key, signature };
}


// ===============================================================================================
module winternitz;

import winternitz_internal @public;
import std::math, std::hash, std::collections::pair;

macro typeid digest_fn($n) @const @local => $typeof(fn char[$n] (char[]) => {});

macro @pow($x, $y) @const @local
{
	$if $y == 0: return 1; $endif
	uint128 $z = $x;
	$for var $i = 2; $i <= $y; ++$i: $z = $z * $x; $endfor
	return $z;
}

struct HashPrng @local
{
	Lcg64Random prng;
	bool seeded;
}
tlocal HashPrng rnd;

<*
 @require $defined($typefrom(digest_fn($n)) b = h) : "The hash function `h` must be the correct type and size"
*>
macro _sign($w, $n, char[] digest, h, char[] private_key = {}, bool wipe_key = false) @local
{
	bool key_generated = false;

	defer
	{
		if (key_generated || wipe_key) foreach (&c : private_key) *c = 0;
		if (key_generated) mem::free(private_key.ptr);
	}

	if (private_key == {})
	{
		key_generated = true;

		if (!rnd.seeded)
		{
			rnd.prng.set_seed(random::entropy()[..]);
			rnd.seeded = true;
		}

		// gen new ephemeral key w/ PRNG
		private_key = mem::new(char[winternitz_internal::LEN{ $w, $n }]);
		foreach (&c : private_key) *c = rnd.prng.next_byte();
	}

	return winternitz_internal::sign{ $w, $n }(digest, private_key, h);
}

macro bool @in(#v, ...) @const @local
{
	$foreach $c : { $vasplat }:
		$if #v == $c: return true; $endif
	$endforeach
	return false;
}

macro private_key_minimum_length($p, $n) @const => winternitz_internal::LEN{ @pow(2, $p), $n };
macro siglen($p, $n) @const => winternitz_internal::LEN{ @pow(2, $p), $n };
macro typeid sigtype($p, $n) @const => (winternitz_internal::Result{ @pow(2, $p), $n }).typeid;

alias WinternitzResult_p2_n32 = $typefrom(sigtype(2, 32));
alias WinternitzResult_p2_n64 = $typefrom(sigtype(2, 64));
alias WinternitzResult_p4_n32 = $typefrom(sigtype(4, 32));
alias WinternitzResult_p4_n64 = $typefrom(sigtype(4, 64));
alias WinternitzResult_p8_n32 = $typefrom(sigtype(8, 32));
alias WinternitzResult_p8_n64 = $typefrom(sigtype(8, 64));
alias WinternitzResult_p16_n32 = $typefrom(sigtype(16, 32));
alias WinternitzResult_p16_n64 = $typefrom(sigtype(16, 64));
alias WinternitzResult_p32_n32 = $typefrom(sigtype(32, 32));
alias WinternitzResult_p32_n64 = $typefrom(sigtype(32, 64));

alias WinternitzSha256 = WinternitzResult_p8_n32;
alias WinternitzSha512 = WinternitzResult_p8_n64;
alias WinternitzShake128 = WinternitzSha256;
alias WinternitzShake256 = WinternitzSha256;

<*
 @require @in($power, 2, 4, 8, 16, 32) : "The power must be 2, 4, 8, 16, or 32"
 @require @in($digest_size, 32, 64) : "The digest length must be 32 or 64"
 @require digest.len == $digest_size : "The compile-time digest size must be the same as the length of the digest field. Are you trying to use a hash size larger than 32 bytes?"
 @require $defined($typefrom(digest_fn($digest_size)) b = h) : "The hash function `h` must be the correct type and size"
*>
macro sign(char[] digest, char[] private_key = {}, h = &sha256::hash, $digest_size = 32, $power = 8, bool wipe_key = false)
{
	return _sign(@pow(2, $power), $digest_size, digest, h, private_key, wipe_key);
}

macro sign_sha256(char[] data, char[] private_key = {}, $power = 8)
{
	return sign(sha256::hash(data)[..], private_key: private_key, h: &sha256::hash,  $power: $power);
}
macro sign_sha512(char[] data, char[] private_key = {}, $power = 8)
{
	return sign(sha512::hash(data)[..], private_key: private_key, h: &sha512::hash, $power: $power, $digest_size: 64);
}

// TODO: after SHA-3 in stdlib
// macro sign_shake128()
// macro sign_shake256()


macro verify(char[] digest, char[] signature, char[] public_key, h = &sha256::hash, $digest_size = 32, $power = 8)
{
	return winternitz_internal::verify{ @pow(2, $power), $digest_size }(digest, signature, public_key);
}

<*
 @require $defined(result.public_key)
 @require $defined(result.signature)
*>
macro verify_result(char[] digest, result, h = &sha256::hash, $digest_size = 32, $power = 8)
{
	return winternitz_internal::verify_result{ @pow(2, $power), $digest_size }(digest, result, h);
}

macro verify_sha256(char[] data, result, $power = 8) => verify_result(sha256::hash(data)[..], result, $power: $power);
macro verify_sha512(char[] data, result, $power = 8) => verify_result(sha512::hash(data)[..], result, h: &sha512::hash, $digest_size: 64, $power: $power);

// TODO: after SHA-3 in stdlib
// macro verify_shake128()
// macro verify_shake256()
