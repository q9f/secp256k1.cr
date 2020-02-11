# secp256k1.cr

[![Build Status](https://img.shields.io/github/workflow/status/q9f/secp256k1.cr/Nightly)](https://github.com/q9f/secp256k1.cr/actions)
[![Documentation](https://img.shields.io/badge/docs-html-black)](https://q9f.github.io/secp256k1.cr/)
[![Release](https://img.shields.io/github/v/release/q9f/secp256k1.cr?include_prereleases&color=black)](https://github.com/q9f/secp256k1.cr/releases/latest)
[![Language](https://img.shields.io/github/languages/top/q9f/secp256k1.cr?color=black)](https://github.com/q9f/secp256k1.cr/search?l=crystal)
[![License](https://img.shields.io/github/license/q9f/secp256k1.cr.svg?color=black)](LICENSE)

a native library implementing `secp256k1` purely for the crystal language. `secp256k1` is the elliptic curve used in the public-private-key cryptography required by bitcoin and ethereum.

this library allows for key generation of:
* private keys (from secure random within the elliptic curve field size)
* mini private keys (short 30-char base-56 keys)
* wallet import format (checksummed base-58 private keys)
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
* managing `enode` addresses as per `devp2p` specification for ethereum nodes

# installation

add the `secp256k1` library to your `shard.yml`

```yaml
dependencies:
  secp256k1:
    github: q9f/secp256k1.cr
    version: "~> 0.3"
```

# usage

_tl;dr,_ check out [`crystal run ./try.cr`](./try.cr)!


```crystal
# import secp256k1
require "secp256k1"
```

this library exposes the following modules (in logical order):

* `Secp256k1`: necessary constants and data structures, including:
  - `Secp256k1::Keypair`: for managing private-public key-pairs
  - `Secp256k1::ECPoint`: for handling of secp256k1 elliptic curve points (public keys)
  - `Secp256k1::ECDSASignature`: for secp256k1 ecdsa signatures
* `Secp256k1::Core`: the entire core mathematics behind the elliptic curve cryptography
* `Secp256k1::Util`: all tools for the handling of private-public key-pairs
* `Secp256k1::Hash`: implementation of various hashing algorithms for convenience
* `Secp256k1::Signature`: allows for signing messages and verifying signatures
* `Secp256k1::Bitcoin`: for the generation of bitcoin addresses, including:
  - `Secp256k1::Bitcoin::Account`: for bitcoin account management
* `Secp256k1::Ethereum`: for the generation of ethereum addresses, including
  - `Secp256k1::Ethereum::Account`: for ethereum account management
  - `Secp256k1::Ethereum::Enode`: for devp2p enode address management

basic usage:

```crystal
# generates a new keypair
key = Secp256k1::Keypair.new
# => #<Secp256k1::Keypair:0x7f8be5611d80>

# gets the private key
key.get_secret
# => "53d77137b39427a35d8c4b187f532d3912e1e7135985e730633e1e3c1b87ce97"

# gets the compressed public key with prefix
compressed = Secp256k1::Util.public_key_compressed_prefix key.public_key
# => "03e097fc69f0b92f711620511c07fefdd648e469df46b1e4385a00a1786f6bc55b"
```

generate a compressed bitcoin mainnet address:

```crystal
# generates a new keypair
key = Secp256k1::Keypair.new
# => #<Secp256k1::Keypair:0x7f8be5611d80>

# generates a compressed bitcoin account from the keypair
btc = Secp256k1::Bitcoin::Account.new key, "00", true
# => #<Secp256k1::Bitcoin::Account:0x7f81ef21ab80>

# gets the wallet-import format (checksummed private key)
btc.wif
# => "Kz2grUzxEAxNopiREbNpVbjoitAGQVXnUZY4n8pNdmWdVqub99qu"

# gets the compressed bitcoin addresss
btc.address
# => "1Q1zbmPZtS2chwxpviqz6qHgoM8UUuviGN"
```

generate a checksummed ethereum address:

```crystal
# generates a new keypair
key = Secp256k1::Keypair.new
# => #<Secp256k1::Keypair:0x7f81ef21ad00>

# generates an ethereum account from the keypair
eth = Secp256k1::Ethereum::Account.new key
# => #<Secp256k1::Ethereum::Account:0x7f81ef1faac0>

# gets the private key
eth.get_secret
# => "53d77137b39427a35d8c4b187f532d3912e1e7135985e730633e1e3c1b87ce97"

# gets the ethereum addresss
eth.address
# => "0x224008a0F3d3cB989c807F568c7f99Bf451328A6"
```

# documentation

the full library documentation can be found here: [q9f.github.io/secp256k1.cr](https://q9f.github.io/secp256k1.cr/)

generate a local copy with:

```
crystal docs
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

* this library is not constant time and might be subject to side-channel attacks. ([#4](https://github.com/q9f/secp256k1.cr/issues/4))
* this library does unnecessary big-integer math and should someday rather correctly implement the secp256k1 prime field ([#5](https://github.com/q9f/secp256k1.cr/issues/5))

found another issue? report it: [github.com/q9f/secp256k1.cr/issues](https://github.com/q9f/secp256k1.cr/issues)

# contribute

create a pull request, and make sure tests and linter passes.

this pure crystal implementation is based on the python implementation [wobine/blackboard101](https://github.com/wobine/blackboard101) which is also used as reference to write tests against. it's a complete rewrite of the abandoned [packetzero/bitcoinutils](https://github.com/packetzero/bitcoinutils) for educational purposes.

honerable mention for the [bitcoin wiki](https://en.bitcoin.it/wiki/Main_Page) and the [ethereum stackexchange](https://ethereum.stackexchange.com/) for providing so many in-depth resources that supported this project in reimplementing everything.

license: apache license v2.0

contributors: [**@q9f**](https://github.com/q9f/)
