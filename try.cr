# Any copyright is dedicated to the Public Domain.
# https://creativecommons.org/publicdomain/zero/1.0/
#
# Contributors: @q9f

require "./src/*"

# everything starts with a new key pair
key_pair = Secp256k1::Keypair.new

# if you feel fancy, you can use a mini private key
fancy = true
if fancy
  private_mini = Secp256k1::Bitcoin.new_mini_private_key
  private_key = Secp256k1::Bitcoin.private_key_from_mini private_mini
  key_pair = Secp256k1::Keypair.new private_key
end

# creates an uncompressed bitcoin account from the key pair
btc = Secp256k1::Bitcoin::Account.new key_pair

# creates a compressed bitcoin account from the same secp256k1 key pair
btc_compr = Secp256k1::Bitcoin::Account.new key_pair, "00", true

# the same but with a different version bit for dogecoin
dog = Secp256k1::Bitcoin::Account.new key_pair, "1e"
dog_compr = Secp256k1::Bitcoin::Account.new key_pair, "1e", true

# creates an ethereum account from the key pair
eth = Secp256k1::Ethereum::Account.new key_pair

# creates a public devp2p enode address from the key pair
p2p = Secp256k1::Ethereum::Enode.new key_pair

# play around with different public key formats
public_compr = Secp256k1::Util.public_key_compressed_prefix key_pair.public_key
public_uncompr = Secp256k1::Util.public_key_uncompressed_prefix key_pair.public_key

# do not proceed if the wallet import format checksum does not pass
exit 101 if !Secp256k1::Bitcoin.wif_is_valid? btc.wif
exit 102 if !Secp256k1::Bitcoin.wif_is_valid? btc_compr.wif
exit 103 if !Secp256k1::Bitcoin.wif_is_valid? dog.wif
exit 104 if !Secp256k1::Bitcoin.wif_is_valid? dog_compr.wif

# let's sign a message
msg = "Hello, World; I am #{btc_compr.address} and #{eth.address}!"
sig = Secp256k1::Signature.sign(msg, key_pair.private_key)
valid = Secp256k1::Signature.verify(msg, sig, key_pair.public_key)

# do not proceed if the signature does not verify
exit 105 if !valid

# let's have a look
puts "Key Magic
---------
                 New private key :   #{Secp256k1::Util.to_padded_hex_32 key_pair.private_key}"
puts "                Mini private key :   #{private_mini}" if fancy
puts "
           Compressed public key : #{public_compr}
          Unompressed public key : #{public_uncompr}
           Unprefixed public key :   #{key_pair.to_s}

Address Magic (all from the same private key)
-------------
          Compressed BTC address :   #{btc_compr.address}
        Uncompressed BTC address :   #{btc.address}
 Compr. BTC Wallet-Import Format :   #{btc_compr.wif}
        BTC Wallet-Import Format :   #{btc.wif}

         Checksummed ETH address : #{eth.address}
        DevP2P ETH Enode address : #{p2p.to_s}

         Compressed DOGE address :   #{dog_compr.address}
       Uncompressed DOGE address :   #{dog.address}
Compr. DOGE Wallet-Import Format :   #{dog_compr.wif}
       DOGE Wallet-Import Format :   #{dog.wif}

Crypto Magic
------------
                     New Message : #{msg}
                       Signature : r=#{Secp256k1::Util.to_padded_hex_32 sig.r}, s=#{Secp256k1::Util.to_padded_hex_32 sig.s}
                 Valid Signature : #{valid}
"
