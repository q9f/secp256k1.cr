# secp256k1.cr

a native library implementing secp256k1 for the crystal language

# installation

add the `secp256k1` library to your `shard.yml`

```yaml
dependencies:
  secp256k1:
    github: q9f/secp256k1.cr
    branch: master
```

# usage

```crystal
# import secp256k1
require "secp256k1"

# generate a keypair
private_key = Secp256k1.new_private_key
public_key = Secp256k1.public_key_from_private private_key

# display the compressed public key
puts Secp256k1.public_key_compressed_prefix public_key
```

# contribute

create a pull request, and make sure tests and linter passes.

this pure crystal implementation is based on the python implementation [wobine/blackboard101](https://github.com/wobine/blackboard101) which is also used as reference to write tests against.

it's a complete rewrite of the abandoned [packetzero/bitcoinutils](https://github.com/packetzero/bitcoinutils) for educational purposes.

