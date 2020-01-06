# secp256k1.cr


[![Badge](https://github.com/q9f/secp256k1.cr/workflows/Nightly/badge.svg)](https://github.com/q9f/secp256k1.cr/actions)
[![Language](https://img.shields.io/github/languages/top/q9f/secp256k1.cr?color=black)](https://github.com/q9f/secp256k1.cr/search?l=crystal)
[![License](https://img.shields.io/github/license/q9f/secp256k1.cr.svg)](LICENSE)

a native library implementing secp256k1 purely for the crystal language. `secp256k1` is the elliptic curve used in the public-private-key cryptography required by bitcoin and ethereum.

this library allows for key generation of:
* private keys (from secure random within the elliptic curve field size)
* mini private keys (short 30-char base-57 keys)
* wallet import format (checksummed private keys)
* public keys, prefixed, compressed (from private)
* public keys, unprefixed and prefixed, uncompressed (from private)
* conversion between the different public key formats

this library allows for address generation of:
* bitcoin address, compressed and uncompressed (from private or public key)
* any other bitcoin-based address by passing a `version` byte
* ethereum address, checksummed and unchecksummed (from private or public key)
* any other ethereum-based address

furthermore, this library allows for:
* signing `(r, s)` and verification of arbitrary messages and message-hashes (with key pairs)

# installation

add the `secp256k1` library to your `shard.yml`

```yaml
dependencies:
  secp256k1:
    github: q9f/secp256k1.cr
    version: "~> 0.2"
```

# usage

_tl;dr,_ check out [`crystal run ./try.cr`](./try.cr)!


```crystal
# import secp256k1
require "secp256k1"
```

this library exposes the following modules (in logical order):

* `Secp256k1`: necessary constants and data structures
* `Secp256k1::Core`: the entire core mathematics behind the elliptic curve cryptography
* `Secp256k1::Utils`: all tools for the handling of private-public key-pairs
* `Secp256k1::Hash`: implementation of various hashing algorithms for convenience
* `Secp256k1::Signature`: allows for signing messages and verifying signatures
* `Secp256k1::Bitcoin`: for the generation of bitcoin addresses
* `Secp256k1::Ethereum`: for the generation of ethereum addresses

basic usage:

```crystal
# generate a keypair
private_key = Secp256k1::Utils.new_private_key
public_key = Secp256k1::Utils.public_key_from_private private_key

# display the compressed public key with prefix
puts Secp256k1::Utils.public_key_compressed_prefix public_key

# > 02b3c141fba20c129806290f04cee097305fb7391abfde01b3bb3affcd935332a1
```

generate a compressed bitcoin mainnet address:

```crystal
# generate a keypair
private_key = Secp256k1::Utils.new_private_key
public_key = Secp256k1::Utils.public_key_from_private private_key
compressed = Secp256k1::Utils.public_key_compressed_prefix public_key

# display the bitcoin address (version "00" for bitcoin mainnet)
puts Secp256k1::Bitcoin.address_from_public_key compressed, "00"

# > "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
```

generate a checksummed ethereum address:

```crystal
# generate a keypair
private_key = Secp256k1::Utils.new_private_key
public_key = Secp256k1::Utils.public_key_from_private private_key
uncompressed = Secp256k1::Utils.public_key_uncompressed public_key

# display the ethereum address
puts Secp256k1::Ethereum.address_from_public_key uncompressed

# > "0x2Ef1f605AF5d03874eE88773f41c1382ac71C239"
```

# testing

the library is entirely specified through tests in `./spec`; run:

```bash
crystal spec --verbose
```

# understand

private keys are just scalars and public keys are points with `x` and `y` coordinates.

bitcoin public keys can be uncompressed `#{p}#{x}#{y}` or compressed `#{p}#{x}`. both come with a prefix `p` which is useless for uncompressed keys but necessary for compressed keys to recover the `y` coordinate on the `secp256k1` elliptic curve.

ethereum public keys are uncompressed `#{x}#{y}` without any prefix. the last 20 bytes slice of the `y` coordinate is actually used as address without any checksum. a checksum was later added in eip-55 using a `keccak256` hash and indicating character capitalization.

neither bitcoin nor ethereum allow for recovering public keys from an address unless there exists a transaction with a valid signature on the blockchain.

# known issues

_note: this library should not be used in production without proper auditing._

* this library is not constant time and might be subject to side-channel attacks. [#4](https://github.com/q9f/secp256k1.cr/issues/4)
* this library does unnecessary big-integer math and should someday rather correctly implement the secp256k1 prime field [#5](https://github.com/q9f/secp256k1.cr/issues/5)

found another issue? report it: https://github.com/q9f/secp256k1.cr/issues

# contribute

create a pull request, and make sure tests and linter passes.

this pure crystal implementation is based on the python implementation [wobine/blackboard101](https://github.com/wobine/blackboard101) which is also used as reference to write tests against. it's a complete rewrite of the abandoned [packetzero/bitcoinutils](https://github.com/packetzero/bitcoinutils) for educational purposes.

honerable mention for the [bitcoin wiki](https://en.bitcoin.it/wiki/Main_Page) and the [ethereum stackexchange](https://ethereum.stackexchange.com/) for providing so many in-depth resources that supported this project in reimplementing everything.

license: apache license v2.0
