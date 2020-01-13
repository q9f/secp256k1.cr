# Copyright 2019-2020 @q9f
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

require "http"
require "socket"

# Implements the `Ethereum` address space for the `Secp256k1` library.
module Secp256k1::Ethereum
  # Implements an `Ethereum` account containing a `Keypair` and an address.
  #
  # Properties:
  # * `key_pair` (`Keypair`): the `Keypair` containing the secret key.
  # * `address` (`String`): the public checksummed `Ethereum` address.
  #
  # ```
  # eth = Secp256k1::Ethereum::Account.new
  # eth.get_secret
  # # => "53d77137b39427a35d8c4b187f532d3912e1e7135985e730633e1e3c1b87ce97"
  # eth.address
  # # => "0x224008a0F3d3cB989c807F568c7f99Bf451328A6"
  # ```
  class Account
    # The `Keypair` containing the secret key.
    property key_pair : Keypair
    # The public checksummed `Ethereum` address.
    property address : String

    # Generates a new `Ethereum::Account` from a fresh random `Keypair`.
    #
    # ```
    # eth = Secp256k1::Ethereum::Account.new
    # # => #<Secp256k1::Ethereum::Account:0x7f81ef21ab80>
    # ```
    def initialize
      @key_pair = Keypair.new
      @address = Ethereum.address_from_private @key_pair.private_key
    end

    # Generates an `Ethereum::Account` from a provided `Keypair`.
    #
    # ```
    # key = Secp256k1::Keypair.new BigInt.new("53d77137b39427a35d8c4b187f532d3912e1e7135985e730633e1e3c1b87ce97", 16)
    # eth = Secp256k1::Ethereum::Account.new key
    # # => #<Secp256k1::Ethereum::Account:0x7f81ef21ab80>
    # ```
    def initialize(@key_pair)
      @address = Ethereum.address_from_private @key_pair.private_key
    end

    # Gets the private key as hexadecimal formatted string literal.
    #
    # ```
    # eth.get_secret
    # # => "53d77137b39427a35d8c4b187f532d3912e1e7135985e730633e1e3c1b87ce97"
    # ```
    def get_secret
      return Util.to_padded_hex_32 @key_pair.private_key
    end

    # Gets the account formatted as `Ethereum` address.
    #
    # ```
    # eth.to_s
    # # => "0x224008a0F3d3cB989c807F568c7f99Bf451328A6"
    # ```
    def to_s
      return Ethereum.address_checksum @address
    end
  end

  # Implements an `Ethereum` devp2p enode containing a `Keypair` and an IP address.
  #
  # Properties:
  # * `key_pair` (`Keypair`): the `Keypair` containing the secret key.
  # * `address` (`Socket::IPAddress`): the public (or local) IP address with port.
  #
  # ```
  # p2p = Secp256k1::Ethereum::Enode.new
  # p2p.get_secret
  # # => "53d77137b39427a35d8c4b187f532d3912e1e7135985e730633e1e3c1b87ce97"
  # p2p.to_s
  # # => "enode://e097fc69f0b92f711620511c07fefdd648e469df46b1e4385a00a1786f6bc55b7d9011bb589e883d8a7947cfb37dc6b3c8beae9c614cab4a83009bd9d8732a9f@84.160.86.205:30303"
  # ```
  class Enode
    # The `Keypair` containing the secret key.
    property key_pair : Keypair
    # The public (or local) IP address with port.
    property address : Socket::IPAddress

    # Generates a new `Ethereum::Enode` from a fresh random `Keypair`.
    #
    # ```
    # p2p = Secp256k1::Ethereum::Enode.new
    # # => #<Secp256k1::Ethereum::Enode:0x7f81ef21ab80>
    # ```
    #
    # Note, this tries to find out the public IP address and silently falls back to "127.0.0.1" if it fails.
    def initialize
      @key_pair = Keypair.new
      @address = Socket::IPAddress.new(get_my_ip, 30303)
    end

    # Generates an `Ethereum::Enode` from a provided `Keypair`.
    #
    # ```
    # key = Secp256k1::Keypair.new BigInt.new("53d77137b39427a35d8c4b187f532d3912e1e7135985e730633e1e3c1b87ce97", 16)
    # p2p = Secp256k1::Ethereum::Enode.new key
    # # => #<Secp256k1::Ethereum::Enode:0x7f81ef21ab80>
    # ```
    #
    # Note, this tries to find out the public IP address and silently falls back to "127.0.0.1" if it fails.
    def initialize(@key_pair)
      @address = Socket::IPAddress.new(get_my_ip, 30303)
    end

    # Generates an `Ethereum::Enode` from a provided `Keypair` and a custom port.
    #
    # ```
    # key = Secp256k1::Keypair.new BigInt.new("53d77137b39427a35d8c4b187f532d3912e1e7135985e730633e1e3c1b87ce97", 16)
    # p2p = Secp256k1::Ethereum::Enode.new key, 50000
    # # => #<Secp256k1::Ethereum::Enode:0x7f81ef21ab80>
    # ```
    #
    # Note, this tries to find out the public IP address and silently falls back to "127.0.0.1" if it fails.
    def initialize(@key_pair, port)
      @address = Socket::IPAddress.new(get_my_ip, port)
    end

    # Generates an `Ethereum::Enode` from a provided `Keypair` and a custom IP address with port.
    #
    # ```
    # key = Secp256k1::Keypair.new BigInt.new("53d77137b39427a35d8c4b187f532d3912e1e7135985e730633e1e3c1b87ce97", 16)
    # p2p = Secp256k1::Ethereum::Enode.new key, "192.168.13.37", 31337
    # # => #<Secp256k1::Ethereum::Enode:0x7f81ef21ab80>
    # ```
    def initialize(@key_pair, host, port)
      @address = Socket::IPAddress.new(host, port)
    end

    # Tries to find out the public IP address for the node.
    #
    # It queries [ident.me](http://ident.me/) for a potential public IP and silently
    # falls back to "127.0.0.1" if it fails without raising. _Should be used with caution._
    #
    # ```
    # p2p.get_my_ip
    # # => "84.160.86.205"
    # ```
    def get_my_ip
      ip = nil

      # Tries to query [ident.me](http://ident.me/) for a potential public IP.
      begin
        ip = HTTP::Client.get("http://ident.me/").body.to_s
      rescue
        # Silently falls back to localhost without raising.
        ip = "127.0.0.1"
      ensure
        # Ensures any IP is set. Falls back to localhost if not.
        ip = "127.0.0.1" if ip.nil? || ip.size < 2
      end
      return ip
    end

    # Gets the private key as hexadecimal formatted string literal.
    #
    # ```
    # p2p.get_secret
    # # => "53d77137b39427a35d8c4b187f532d3912e1e7135985e730633e1e3c1b87ce97"
    # ```
    def get_secret
      return Util.to_padded_hex_32 @key_pair.private_key
    end

    # Gets the `Enode` formatted as devp2p enode address.
    #
    # ```
    # p2p.to_s
    # # => "enode://e097fc69f0b92f711620511c07fefdd648e469df46b1e4385a00a1786f6bc55b7d9011bb589e883d8a7947cfb37dc6b3c8beae9c614cab4a83009bd9d8732a9f@84.160.86.205:30303"
    # ```
    def to_s
      return "enode://#{@key_pair.to_s}@#{@address.to_s}"
    end
  end

  # Returns a checksummed `Ethereum` address as per EIP-55.
  #
  # Reference: [eips.ethereum.org/EIPS/eip-55](https://eips.ethereum.org/EIPS/eip-55)
  #
  # Parameters:
  # * `adr` (`String`): an unchecked `Ethereum` address.
  #
  # ```
  # Secp256k1::Ethereum.address_checksum "0x7598c0fbaeb021161ce2e598f45ddee90fe5c6f7"
  # # => "0x7598c0FBAEB021161ce2E598F45dDEe90FE5C6f7"
  # ```
  #
  # Raises if address is malformed.
  def self.address_checksum(adr : String)
    # Makes sure the address is lower case.
    adr = adr.downcase

    if adr.size === 42
      # Trims a leading `"0x"`.
      adr = adr[2, 40]
    end

    if adr.size === 40
      # Gets a Keccak-256 hash to operate on according to EIP-55.
      keccak = Hash.keccak256_string adr

      # Prefixes the address with `"0x"`.
      address = "0x"

      # Iterates each character to determine capitalization.
      i = 0
      while i < adr.size
        k = keccak[i].to_i 16
        if k >= 8
          address += "#{adr[i]}".upcase
        else
          address += "#{adr[i]}".downcase
        end
        i += 1
      end
      return address
    else
      raise "malformed ethereum address (invalid size: #{adr.size})"
    end
    return "-999"
  end

  # Generates a checksummed `Ethereum` address for an uncompressed public key.
  #
  # Parameters:
  # * `pub` (`String`): an uncompressed public key string.
  #
  # ```
  # Secp256k1::Ethereum.address_from_public_key "d885aed4bcaf3a8c95a57e3be08caa1bd6a060a68b9795c03129073597fcb19a67299d1cf25955e9b6425583cbc33f4ab831f5a31ef88c7167e9eb714cc758a5"
  # # => "0x7598c0FBAEB021161ce2E598F45dDEe90FE5C6f7"
  # ```
  #
  # Note, that the returned `Ethereum` address is already checksummed.
  #
  # Raises if the public key is malformed.
  def self.address_from_public_key(pub : String)
    if pub.size === 130
      # Trims a leading prefix.
      pub = pub[2, 128]
    end

    # Ensures to use uncompressed public keys.
    if pub.size === 128
      # Hashes the uncompressed public key with Keccak-256.
      keccak = Hash.keccak256 Hash.hex_to_bin pub

      # Takes the last 20 bytes from the hash
      return address_checksum keccak[24, 40]
    else
      raise "malformed public key (invalid key size: #{pub.size})"
    end
    return "-999"
  end

  # Generates a checksummed `Ethereum` address from an public key as `EC_Point`.
  #
  # Parameters:
  # * `p` (`EC_Point`): a public key point with `x` and `y` coordinates.
  #
  # See `address_from_public_key` and `EC_Point` for usage instructions.
  def self.address_from_public_point(p : Secp256k1::EC_Point)
    # Takes the corresponding public key generated with it.
    pub = Secp256k1::Util.public_key_uncompressed p
    return address_from_public_key pub
  end

  # Generates a checksummed `Ethereum` address from a private key.
  #
  # Parameters:
  # * `priv` (`BigInt`): a private key as number.
  #
  # ```
  # Secp256k1::Ethereum.address_from_private BigInt.new("b795cd2c5ce0cc632ca1f65e921b9c751b363e97fcaeec81c02a85b763448268", 16)
  # # => "0x7598c0FBAEB021161ce2E598F45dDEe90FE5C6f7"
  # ```
  #
  # Note, that the returned `Ethereum` address is already checksummed.
  def self.address_from_private(priv : BigInt)
    # Takes the corresponding public key generated with it.
    p = Secp256k1::Util.public_key_from_private priv
    return address_from_public_point p
  end
end
