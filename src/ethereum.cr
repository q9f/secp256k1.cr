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

# implements the Ethereum address space
module Secp256k1::Ethereum
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
      keccak = Hash.keccak256_string adr

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
      keccak = Hash.keccak256 pub

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
    pub = Secp256k1::Utils.public_key_uncompressed p
    return address_from_public_key pub
  end

  # generates an ethereum address from a private key
  def self.address_from_private(priv : String)
    # having a private ecdsa key
    # take the corresponding public key generated with it
    priv = BigInt.new priv, 16
    p = Secp256k1::Utils.public_key_from_private priv
    return address_from_public_point p
  end
end
