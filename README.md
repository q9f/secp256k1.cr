# secp256k1.cr

[![Build Status](https://img.shields.io/github/workflow/status/q9f/secp256k1.cr/Nightly)](https://github.com/q9f/secp256k1.cr/actions)
[![Code Coverage](https://codecov.io/gh/q9f/secp256k1.cr/branch/main/graph/badge.svg?token=ngxRs9HdJA)](https://codecov.io/gh/q9f/secp256k1.cr)
[![Documentation](https://img.shields.io/badge/docs-html-black)](https://q9f.github.io/secp256k1.cr/)
[![Release](https://img.shields.io/github/v/release/q9f/secp256k1.cr?include_prereleases&color=black)](https://github.com/q9f/secp256k1.cr/releases/latest)
[![Language](https://img.shields.io/github/languages/top/q9f/secp256k1.cr?color=black)](https://github.com/q9f/secp256k1.cr/search?l=crystal)
[![License](https://img.shields.io/github/license/q9f/secp256k1.cr.svg?color=black)](LICENSE)

A library implementing the `Secp256k1` elliptic curve natively in pure Crystal.
`Secp256k1` is the elliptic curve used in the public-private-key cryptography required by `Bitcoin`, `Ethereum`, and `Polkadot`.

This library allows for:
* providing a `Secp256k1` cryptographic context, see `Secp256k1::Context`
* managing `Secp256k1` signatures and verification, see `Secp256k1::Signature`
* managing private-public keypairs, see `Secp256k1::Key`
* generating public keys, see `Secp256k1::Point`
* generating private keys, see `Secp256k1::Num`

# Installation

Add the `Secp256k1` library to your `shard.yml`

```yaml
dependencies:
  secp256k1:
    github: q9f/secp256k1.cr
    version: "~> 0.5"
```

# Usage

Import and expose the `Secp256k1` module.

```crystal
require "secp256k1"
```

This library exposes the following modules and classes (in logical order):

* `Secp256k1`: necessary constants and data structures, including:
  - `Secp256k1::Num`: for managing big numerics (private keys)
  - `Secp256k1::Point`: for handling of elliptic curve points (public keys)
  - `Secp256k1::Key`: for managing private-public keypairs (accounts)
  - `Secp256k1::Signature`: for handling ECDSA signatures (r, s, v)
* `Secp256k1::Context`: providing a cryptographic context for signing and verification
* `Secp256k1::Curve`: the entire core mathematics behind the elliptic curve cryptography
* `Secp256k1::Util`: binding of various hashing algorithms for convenience

Basic usage:

```crystal
# generates a new, random keypair
key = Secp256k1::Key.new
# => #<Secp256k1::Key:0x7fad7235aee0
#          @private_key=#<Secp256k1::Num:0x7fad7235d300
#              @hex="3ccf84820c20d5e8c536ba84c52ba410375b29b1812b5f7e722445c969a0fb30",
#              @dec=27505422793993207218034260454067205887515304192802142316084292370834437241648,
#              @bin=Bytes[60, 207, 132, 130, 12, 32, 213, 232, 197, 54, 186, 132, 197, 43, 164, 16, 55, 91, 41, 177, 129, 43, 95, 126, 114, 36, 69, 201, 105, 160, 251, 48]>,
#          @public_key=#<Secp256k1::Point:0x7fad7235ad20
#              @x=#<Secp256k1::Num:0x7fad69294ec0
#                  @hex="cd4a8712ee6efc15b5abe37c0dbfa979d89c427d3fe24b076008decefe94dba2",
#                  @dec=92855812888509048668847240903552964511053624688683992093822247249407942908834,
#                  @bin=Bytes[205, 74, 135, 18, 238, 110, 252, 21, 181, 171, 227, 124, 13, 191, 169, 121, 216, 156, 66, 125, 63, 226, 75, 7, 96, 8, 222, 206, 254, 148, 219, 162]>,
#              @y=#<Secp256k1::Num:0x7fad69294e80
#                  @hex="81363d298e4a40ebcb13f1afa85a0b94b967f243ee59a59010cb5deaf0d7b66c",
#                  @dec=58444189335609256006902338825877424261513225250255958585656342678587884156524,
#                  @bin=Bytes[129, 54, 61, 41, 142, 74, 64, 235, 203, 19, 241, 175, 168, 90, 11, 148, 185, 103, 242, 67, 238, 89, 165, 144, 16, 203, 93, 234, 240, 215, 182, 108]>>>

# gets the private key
key.private_hex
# => "3ccf84820c20d5e8c536ba84c52ba410375b29b1812b5f7e722445c969a0fb30"

# gets the compressed public key with prefix
key.public_hex_compressed
# => "02cd4a8712ee6efc15b5abe37c0dbfa979d89c427d3fe24b076008decefe94dba2"
```

Signature generation and verification:

```crystal
# sign a message with a private key
ctx = Secp256k1::Context.new
priv = Secp256k1::Num.new "1f0c122d41ff536b19bfd83537c0dfc290e45cd3c375a43237c8b8fff7ac8af7"
key = Secp256k1::Key.new priv
hash = Secp256k1::Util.sha256 "Henlo, Wordl"
sig = ctx.sign key, hash
# => #<Secp256k1::Signature:0x7f5332e1d9c0
#          @r=#<Secp256k1::Num:0x7f5332decac0
#              @hex="c4079db44240b7afe94985c69fc89602e33629fd9b8623d711c30ce6378b33df",
#              @dec=88666774685717741514025410921892109286073075687452443491001272268566542627807,
#              @bin=Bytes[196, 7, 157, 180, 66, 64, 183, 175, 233, 73, 133, 198, 159, 200, 150, 2, 227, 54, 41, 253, 155, 134, 35, 215, 17, 195, 12, 230, 55, 139, 51, 223]>,
#          @s=#<Secp256k1::Num:0x7f5332deca80
#              @hex="6842c1b63c94bdb8e4f5ae88fb65f7a98b77b197c8323004fb47ef57fab29053",
#              @dec=47158485109070227797431103290229472044663017260590156038384319099500326195283,
#              @bin=Bytes[104, 66, 193, 182, 60, 148, 189, 184, 228, 245, 174, 136, 251, 101, 247, 169, 139, 119, 177, 151, 200, 50, 48, 4, 251, 71, 239, 87, 250, 178, 144, 83]>,
#          @v=#<Secp256k1::Num:0x7f5332deca40
#              @hex="00",
#              @dec=0,
#              @bin=Bytes[0]>>

# verify a signature with a public key
r = Secp256k1::Num.new "c4079db44240b7afe94985c69fc89602e33629fd9b8623d711c30ce6378b33df"
s = Secp256k1::Num.new "6842c1b63c94bdb8e4f5ae88fb65f7a98b77b197c8323004fb47ef57fab29053"
v = Secp256k1::Num.new "00"
sig = Secp256k1::Signature.new r, s, v
hash = Secp256k1::Util.sha256 "Henlo, Wordl"
publ = Secp256k1::Point.new "0416008a369439f1a8a75cf974860bed5b10180518d6b1dd3ac847f423fd375d6aa29474394f0cd79d2ea543507d069e97339284f01bdbfd27392daec0ec553816"
ctx.verify sig, hash, publ
# => true
```

There are example scripts for generating `Bitcoin` and `Ethereum` accounts in `src/bitcoin.cr` and `src/ethereum.cr`.

# Documentation

The full library documentation can be found here: [q9f.github.io/secp256k1.cr](https://q9f.github.io/secp256k1.cr/)

Generate a local copy with:

```shell
crystal docs
```

# Testing

The library is entirely specified through tests in `./spec`; run:

```shell
crystal spec --verbose
```

# Understand

Private keys are just scalars (`Secp256k1::Num`) and public keys are points (`Secp256k1::Point`) with `x` and `y` coordinates.

Bitcoin public keys can be uncompressed `p|x|y` or compressed `p|x`. both come with a prefix `p` which is useless for uncompressed keys but necessary for compressed keys to recover the `y` coordinate on the `Secp256k1` elliptic curve field.

Ethereum public keys are uncompressed `x|y` without any prefix. The last 20 bytes slice of the `y` coordinate is actually used as address without any checksum. A checksum was later added in EIP-55 using a `keccak256` hash and indicating character capitalization.

Neither Bitcoin nor Ethereum allow for recovering public keys from an address unless there exists a transaction with a valid signature on the blockchain.

# Known issues

_Note: this library should not be used in production without proper auditing. It should be considered slow and insecure._

* This library is not constant time and might be subject to side-channel attacks. ([#4](https://github.com/q9f/secp256k1.cr/issues/4))
* This library does unnecessary big-integer math and should someday rather correctly implement the `Secp256k1` prime field ([#5](https://github.com/q9f/secp256k1.cr/issues/5))
* This library is slow in recovering signatures. Future versions should respect the recovery ID to quickly identify the correct public key from a signature.

Found any other issue? Report it: [github.com/q9f/secp256k1.cr/issues](https://github.com/q9f/secp256k1.cr/issues)

# Contribute

Create a pull request, and make sure tests and linter pass.

This pure crystal implementation is based on the python implementation [wobine/blackboard101](https://github.com/wobine/blackboard101) which is also used as reference to write tests against. It's a complete rewrite of the abandoned [packetzero/bitcoinutils](https://github.com/packetzero/bitcoinutils) for educational purposes.

Honerable mention for the [bitcoin wiki](https://en.bitcoin.it/wiki/Main_Page) and the [ethereum stackexchange](https://ethereum.stackexchange.com/) for providing so many in-depth resources that supported this project in reimplementing everything.

License: Apache License v2.0

Contributors: [**@q9f**](https://github.com/q9f/), [@cserb](https://github.com/cserb), [MrSorcus](https://github.com/MrSorcus)
