require "./src/*"

# everything starts with a random number
private_key = Secp256k1::Utils.new_private_key

# if you feel fancy, you can use a mini private key
fancy = true
if fancy
  private_mini = Secp256k1::Bitcoin.new_mini_private_key
  private_key = Secp256k1::Bitcoin.private_key_from_mini private_mini
end

# private keys in bitcoin's wallet import format
wif = Secp256k1::Bitcoin.wif_from_private private_key, "80"

# private keys in bitcoin's wallet import format (compressed)
wif_compr = Secp256k1::Bitcoin.wif_compressed_from_private private_key, "80"

# the point on the elliptic curve is our public key
public_key = Secp256k1::Utils.public_key_from_private private_key

# compressed public keys for compressed bitcoin addresses
public_compr = Secp256k1::Utils.public_key_compressed_prefix public_key
btc_compr = Secp256k1::Bitcoin.address_from_public_key public_compr, "00"

# prefixed uncompressed public keys for normal bitcoin addresses
public_uncompr_4 = Secp256k1::Utils.public_key_uncompressed_prefix public_key
btc_uncompr = Secp256k1::Bitcoin.address_from_public_key public_uncompr_4, "00"

# uncompressed public keys for ethereum addresses
public_uncompr = Secp256k1::Utils.public_key_uncompressed public_key
eth = Secp256k1::Ethereum.address_from_public_key public_uncompr

# pass a different version byte to get a DOGE address
dog_compr = Secp256k1::Bitcoin.address_from_public_key public_compr, "1e"
dog_uncompr = Secp256k1::Bitcoin.address_from_public_key public_uncompr_4, "1e"
dog_wif = Secp256k1::Bitcoin.wif_from_private private_key, "9e"
dog_wif_compr = Secp256k1::Bitcoin.wif_compressed_from_private private_key, "9e"

# do not proceed if the wallet import format checksum does not pass
exit 101 if !Secp256k1::Bitcoin.wif_is_valid? wif
exit 102 if !Secp256k1::Bitcoin.wif_is_valid? wif_compr
exit 103 if !Secp256k1::Bitcoin.wif_is_valid? dog_wif
exit 104 if !Secp256k1::Bitcoin.wif_is_valid? dog_wif_compr

# let's sign a message
msg = "Hello, World; I am #{btc_compr}!"
sig = Secp256k1::Signature.sign(msg, private_key)
valid = Secp256k1::Signature.verify(msg, sig, public_key)

# let's have a look
puts "Key Magic
---------
                 New private key :   #{Secp256k1::Utils.to_padded_hex_32 private_key}"
puts "                Mini private key :   #{private_mini}" if fancy
puts "
           Compressed public key : #{public_compr}
          Unompressed public key : #{public_uncompr_4}
           Unprefixed public key :   #{public_uncompr}

Address Magic (all from the same private key)
-------------
          Compressed BTC address :   #{btc_compr}
        Uncompressed BTC address :   #{btc_uncompr}
 Compr. BTC Wallet Import Format :   #{wif_compr}
        BTC Wallet Import Format :   #{wif}

         Checksummed ETH address : #{eth}

         Compressed DOGE address :   #{dog_compr}
       Uncompressed DOGE address :   #{dog_uncompr}
Compr. DOGE Wallet Import Format :   #{dog_wif_compr}
       DOGE Wallet Import Format :   #{dog_wif}

Crypto Magic
------------
                     New Message : #{msg}
                       Signature : r=#{Secp256k1::Utils.to_padded_hex_32 sig.r}, s=#{Secp256k1::Utils.to_padded_hex_32 sig.s}
                 Valid Signature : #{valid}
"
