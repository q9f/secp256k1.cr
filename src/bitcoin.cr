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

# Implements the Bitcoin address space for the `Secp256k1` library.
module Secp256k1::Bitcoin
  # Generates a new mini-private key (30 characters length, Base-56 encoded).
  #
  # ```
  # Secp256k1::Bitcoin.new_mini_private_key
  # # => StQgmn4NaWWoDyTS9zXbfH27BmRhx2
  # ```
  def self.new_mini_private_key
    valid = false
    key = String.new
    until valid
      i = 1

      # Mini-private keys always start with a capital `S`.
      key = "S"

      # Add 29 random characters from the Base-56 alphabet.
      while i < 30
        i += 1
        r = Random.rand 56
        key += Hash.base56_char r
      end

      # It's only a valid mini-private key if the hash of `#{key}?` starts with `"00"`.
      checksum = Hash.sha256_string "#{key}?"
      valid = checksum[0, 2] === "00"

      # It's only valid if the private key is within the Secp256k1 field size `n`.
      priv = private_key_from_mini key
      valid = valid && priv > 0
      valid = valid && priv === priv % Secp256k1::EC_ORDER_N
    end
    return key
  end

  # Gets a private key from a mini-private key.
  #
  # ```
  # Secp256k1::Bitcoin.private_key_from_mini "StQgmn4NaWWoDyTS9zXbfH27BmRhx2"
  # # => b795cd2c5ce0cc632ca1f65e921b9c751b363e97fcaeec81c02a85b763448268
  # ```
  def self.private_key_from_mini(m : String)
    # The private key is just the SHA-256 hash.
    private_key = Hash.sha256_string m
    return BigInt.new private_key, 16
  end

  # Gets a Base-58 Wallet-Import Format (WIF) from a private key.
  #
  # Parameters:
  # * `k` (`BigInt`): the private key
  # * `version` (`String`): the version byte, default: `"80"` (Bitcoin)
  # * `compr` (`String`): the compression byte, default: `""` (uncompressed)
  #
  # ```
  # Secp256k1::Bitcoin.wif_from_private BigInt.new("b795cd2c5ce0cc632ca1f65e921b9c751b363e97fcaeec81c02a85b763448268", 16)
  # # => 5KD92145CyrZhXh6oGbawrkE32wukC1KwUtmQpSJ4dGiUTAWPdd
  # ```
  def self.wif_from_private(k : BigInt, version = "80", compr = "")
    # Take the private key.
    priv = Secp256k1::Util.to_padded_hex_32 k

    # Prepend the version byte and append the compression byte.
    versioned = "#{version}#{priv}#{compr}"

    # Perform a SHA-256 hash on the extended key.
    hashed = Hash.sha256 Hash.hex_to_bin versioned

    # Perform a SHA-256 hash on the result of the SHA-256 hash.
    hashed_twice = Hash.sha256 Hash.hex_to_bin hashed

    # Take the first four bytes of the second SHA-256 hash, this is the checksum.
    # Add the four checksum bytes at the end of the versioned key.
    binary = "#{versioned}#{hashed_twice[0, 8]}"

    # Convert the result from a byte string into a Base-58 string.
    # This is the Wallet-Import Format (WIF).
    return Hash.base58_encode binary
  end

  # Gets a compressed Base-58 Wallet-Import Format (WIF) from a private key.
  #
  # Parameters:
  # * `k` (`BigInt`): the private key
  # * `version` (`String`): the version byte, default: `"80"` (Bitcoin)
  #
  # ```
  # Secp256k1::Bitcoin.wif_compressed_from_private BigInt.new("b795cd2c5ce0cc632ca1f65e921b9c751b363e97fcaeec81c02a85b763448268", 16)
  # # => L3NaPREZZswmKtTzbDqeq8ZnXybModaSbU7V28NeK16N3nkA8jcp
  # ```
  def self.wif_compressed_from_private(k : BigInt, version = "80")
    # To indicate a compressed key to be used, append a `"01"` byte.
    return wif_from_private k, version, "01"
  end

  # gets a private key from a wallet import format
  def self.private_key_from_wif(w : String)
    # decoding base58 contains the checksummed private key
    checksum_key = Hash.base58_decode w

    # the key must be 37 bytes (uncompressed) or 38 bytes (compressed)
    if checksum_key.size == 74 || checksum_key.size == 76
      # drop the version byte, checksum, and compressed byte
      private_key = BigInt.new checksum_key[2, 64], 16
      return Secp256k1::Util.to_padded_hex_32 private_key
    else
      raise "invalid wallet import format (invalid wif size: #{checksum_key.size})"
      return "-999"
    end
  end

  # gets the version byte from a wallet import format
  def self.version_byte_from_wif(w : String)
    # decoding base58 contains the versioned private key
    versioned = Hash.base58_decode w

    # the key must be 37 bytes (uncompressed) or 38 bytes (compressed)
    if versioned.size === 74 || versioned.size === 76
      # extract the version byte
      return versioned[0, 2]
    else
      raise "invalid wallet import format (invalid wif size: #{versioned.size})"
      return "-999"
    end
  end

  # checks if it's compressed or uncompressed wallet import format
  def self.is_wif_compressed?(w : String)
    # decoding base58 contains the versioned private key
    versioned = Hash.base58_decode w

    # the key must be 37 bytes (uncompressed) or 38 bytes (compressed)
    if versioned.size === 74 || versioned.size === 76
      # true if compressed
      return versioned.size === 76
    else
      raise "invalid wallet import format (invalid wif size: #{versioned.size})"
      return "-999"
    end
  end

  # validates wether a wif has a correct checksum
  def self.wif_is_valid?(w : String)
    # decoding base58 contains the checksummed private key
    checksum_key = Hash.base58_decode w

    # the key must be 37 bytes (uncompressed) or 38 bytes (compressed)
    valid = checksum_key.size === 74 || checksum_key.size === 76

    # only proceed if wif is valid
    if valid
      # ensure the private key is valid
      private_key = private_key_from_wif w
      valid = valid && private_key != "-999" && private_key.size === 64

      # drop the checksum bytes
      versioned = checksum_key[0, 66]
      wif_checksum = checksum_key[66, 8]

      # make sure to honor the compression byte
      if checksum_key.size === 76
        versioned = checksum_key[0, 68]
        wif_checksum = checksum_key[68, 8]
      end

      # perform sha-256 hash on the versioned key
      # perform sha-256 hash on result of sha-256 hash
      hashed = Hash.sha256 Hash.hex_to_bin versioned
      hashed_twice = Hash.sha256 Hash.hex_to_bin hashed

      # check the wif checksum against the private key checksum
      pk_checksum = hashed_twice[0, 8]
      valid = valid && wif_checksum === pk_checksum
    end
    return valid
  end

  # generates a bitcoin address for any public key; compressed and uncompressed
  # version 0x00 = btc mainnet; pass different versions for different networks
  def self.address_from_public_key(pub : String, version = "00")
    # ensure uncompressed or compressed public keys with prefix
    if pub.size === 130 || pub.size === 66
      # perform sha-256 hashing on the public key
      sha2 = Hash.sha256 Hash.hex_to_bin pub

      # perform ripemd-160 hashing on the result of sha-256
      ripe = Hash.ripemd160 Hash.hex_to_bin sha2

      # add version byte in front of ripemd-160 hash
      ripe_versioned = "#{version}#{ripe}"

      # perform sha-256 hash on the extended ripemd-160 result
      # perform sha-256 hash on the result of the previous sha-256 hash
      hashed = Hash.sha256 Hash.hex_to_bin ripe_versioned
      hashed_twice = Hash.sha256 Hash.hex_to_bin hashed

      # take the first 4 bytes of the second sha-256 hash; this is the address checksum
      # add the 4 checksum bytes at the end of extended ripemd-160 hash
      # this is the 25-byte binary bitcoin address
      binary = "#{ripe_versioned}#{hashed_twice[0, 8]}"

      # convert the result from a byte string into a base58 string
      # this is the most commonly used bitcoin address format
      return Hash.base58_encode binary
    else
      raise "malformed public key (invalid key size: #{pub.size})"
    end
    return "-999"
  end

  # generates a bitcoin address from an public key ec point
  def self.address_from_public_point(p : Secp256k1::EC_Point, version = "00", compressed = true)
    # take the corresponding public key generated with it
    pub = Secp256k1::Util.public_key_uncompressed_prefix p

    # generate a compressed address if specified
    pub = Secp256k1::Util.public_key_compressed_prefix p if compressed
    return address_from_public_key pub, version
  end

  # gets a bitcoin address from a wif key
  def self.address_from_wif(wif : String)
    if wif_is_valid? wif
      # gets the version byte from wif
      vers = version_byte_from_wif wif
      vers = vers.to_i 16

      # the version byte of the public address is offset by -128
      vers -= 128

      # make sure the version byte is properly padded
      vers = Secp256k1::Util.to_padded_hex_01 vers

      # gets the private key from the wif
      priv = private_key_from_wif wif

      # checks wether we want compressed or uncompressed address
      comp = is_wif_compressed? wif

      return address_from_private priv, vers, comp
    else
      raise "invalid wallet import format (invalid wif: #{wif})"
      return "-999"
    end
  end

  # generates a bitcoin address from a private key
  def self.address_from_private(priv : String, version = "00", compressed = true)
    # having a private ecdsa key
    # take the corresponding public key generated with it
    priv = BigInt.new priv, 16
    p = Secp256k1::Util.public_key_from_private priv
    return address_from_public_point p, version, compressed
  end
end
