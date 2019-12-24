# Copyright 2019 @q9f
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# implements the bitcoin address space
module Bitcoin
  # generates a bitcoin address for any public key; compressed and uncompressed
  # version 0x00 = btc mainnet; pass different versions for different networks
  def self.address_from_public_key(pub : String, version = "00")
    # ensure uncompressed or compressed public keys with prefix
    if pub.size === 130 || pub.size === 66
      # perform sha-256 hashing on the public key
      sha2 = Crypto.sha256 pub

      # perform ripemd-160 hashing on the result of sha-256
      ripe = Crypto.ripemd160 sha2

      # add version byte in front of ripemd-160 hash
      ripe_versioned = "#{version}#{ripe}"

      # perform sha-256 hash on the extended ripemd-160 result
      # perform sha-256 hash on the result of the previous sha-256 hash
      hashed = Crypto.sha256 ripe_versioned
      hashed_twice = Crypto.sha256 hashed

      # take the first 4 bytes of the second sha-256 hash; this is the address checksum
      # add the 4 checksum bytes at the end of extended ripemd-160 hash
      # this is the 25-byte binary bitcoin address
      binary = "#{ripe_versioned}#{hashed_twice[0, 8]}"

      # convert the result from a byte string into a base58 string
      # this is the most commonly used bitcoin address format
      return Crypto.base58 binary
    else
      raise "malformed public key (invalid key size: #{pub.size})"
    end
    return "-999"
  end

  # generates a bitcoin address from an public key ec point
  def self.address_from_public_point(p : Secp256k1::EC_Point, version = "00")
    # take the corresponding public key generated with it
    pub = Secp256k1.public_key_compressed_prefix p
    return address_from_public_key pub, version
  end

  # generates a bitcoin address from a private key
  def self.address_from_private(priv : String, version = "00")
    # having a private ecdsa key
    # take the corresponding public key generated with it
    priv = BigInt.new priv, 16
    p = Secp256k1.public_key_from_private priv
    return address_from_public_point p, version
  end
end

# implements the Ethereum address space
module Ethereum
  # returns a checksummed ethereum address as per eip-55
  def self.address_checksum(adr : String)
    # make sure the address is downcase
    adr = adr.downcase

    if adr.size === 42
      # trim a leading `0x`
      adr = adr[2, 40]
    end

    if adr.size === 40
      # get a keccak-256 to operate on according to eip-55
      keccak = Crypto.keccak256_string adr

      # prefix the address with `0x`
      address = "0x"

      # iterate each character to determine capitalization
      i = 0
      while i < adr.size
        k = keccak[i].to_i 16
        if k >= 8
          address += "#{adr[i]}".upcase
        else
          address += "#{adr[i]}"
        end
        i += 1
      end
      return address
    else
      raise "malformed ethereum address (invalid size: #{adr.size})"
    end
    return "-999"
  end

  # generates an ethereum address for an uncompressed public key
  def self.address_from_public_key(pub : String)
    # ensure uncompressed public keys
    if pub.size === 128
      # hashes the uncompressed public key with keccak-256
      keccak = Crypto.keccak256 pub

      # take the last 20 bytes from the hash
      return address_checksum keccak[24, 40]
    else
      raise "malformed public key (invalid key size: #{pub.size})"
    end
    return "-999"
  end

  # generates an ethereum address from an public key ec point
  def self.address_from_public_point(p : Secp256k1::EC_Point)
    # take the corresponding public key generated with it
    pub = Secp256k1.public_key_uncompressed p
    return address_from_public_key pub
  end

  # generates an ethereum address from a private key
  def self.address_from_private(priv : String)
    # having a private ecdsa key
    # take the corresponding public key generated with it
    priv = BigInt.new priv, 16
    p = Secp256k1.public_key_from_private priv
    return address_from_public_point p
  end
end