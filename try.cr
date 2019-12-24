require "./src/*"

# everything starts with a random number
private_key = Secp256k1.new_private_key

# if you feel fancy, you can use a mini private key
fancy = true
if fancy
  private_mini = Bitcoin.new_mini_private_key
  private_key = Bitcoin.private_key_from_mini private_mini
end

# the point on the elliptic curve is our public key
public_key = Secp256k1.public_key_from_private private_key

# compressed public keys for compressed bitcoin addresses
public_compr = Secp256k1.public_key_compressed_prefix public_key
btc_compr = Bitcoin.address_from_public_key public_compr, "00"

# prefixed uncompressed public keys for normal bitcoin addresses
public_uncompr_4 = Secp256k1.public_key_uncompressed_prefix public_key
btc_uncompr = Bitcoin.address_from_public_key public_uncompr_4, "00"

# uncompressed public keys for ethereum addresses
public_uncompr = Secp256k1.public_key_uncompressed public_key
eth = Ethereum.address_from_public_key public_uncompr

# pass a different version byte to get a DOGE address
dog_compr = Bitcoin.address_from_public_key public_compr, "1e"
dog_uncompr = Bitcoin.address_from_public_key public_uncompr_4, "1e"

# let's have a look
puts "
          New private key:   #{private_key.to_s 16}"
puts "         Mini private key:   #{private_mini}" if fancy
puts "                         :
    Compressed public key: #{public_compr}
   Unompressed public key: #{public_uncompr_4}
    Unprefixed public key:   #{public_uncompr}
                         :
   Compressed BTC address:   #{btc_compr}
 Uncompressed BTC address:   #{btc_uncompr}
                         :
  Checksummed ETH address:   #{eth}
                         :
  Compressed DOGE address:   #{dog_compr}
Uncompressed DOGE address:   #{dog_uncompr}
                         :
                         ^ All from the same private key.
"
