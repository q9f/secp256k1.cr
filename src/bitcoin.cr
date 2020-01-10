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

# Implements the `Bitcoin` address space for the `Secp256k1` library.
module Secp256k1::Bitcoin
  class Account
    property key_pair : Keypair
    property version : String
    property compressed : Bool
    property address : String
    property wif : String

    def initialize
      @key_pair = Keypair.new
      @version = "00"
      @compressed = false
      @address = Bitcoin.address_from_private @key_pair.private_key, @version, @compressed
      @wif = Bitcoin.wif_from_private_uncompressed @key_pair.private_key, version_wif
    end

    def initialize(@key_pair)
      @version = "00"
      @compressed = false
      @address = Bitcoin.address_from_private @key_pair.private_key, @version, @compressed
      @wif = Bitcoin.wif_from_private_uncompressed @key_pair.private_key, version_wif
    end

    def initialize(@key_pair, @version)
      v = @version.to_i 16
      if !v.nil? && v >= 0 && v < 128
        @compressed = false
        @address = Bitcoin.address_from_private @key_pair.private_key, @version, @compressed
        @wif = Bitcoin.wif_from_private_uncompressed @key_pair.private_key, version_wif
      else
        raise "invalid version byte provided (out of range: #{@version})"
      end
    end

    def initialize(@key_pair, @version, @compressed)
      v = @version.to_i 16
      if !v.nil? && v >= 0 && v < 128
        @address = Bitcoin.address_from_private @key_pair.private_key, @version, @compressed
        if compressed
          @wif = Bitcoin.wif_from_private_compressed @key_pair.private_key, version_wif
        else
          @wif = Bitcoin.wif_from_private_uncompressed @key_pair.private_key, version_wif
        end
      else
        raise "invalid version byte provided (out of range: #{@version})"
      end
    end

    def is_compressed?
      return @compressed
    end

    def version_wif
      return Util.to_padded_hex_01(@version.to_i(16) + 128)
    end

    def get_secret
      return Util.to_padded_hex_32 @key_pair.private_key
    end

    def to_s
      return @address
    end
  end

  # Generates a new mini-private key (30 characters length, Base-56 encoded).
  #
  # ```
  # Secp256k1::Bitcoin.new_mini_private_key
  # # => S7qq5k98DAvee6mtQgpg4xAJatT9mR
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

      # Makes sure the key's checksum passes.
      valid = mini_is_valid? key
      if valid
        # It's only valid if the private key is within the `Secp256k1` field size `n`.
        priv = private_key_from_mini key
        valid = valid && priv > 0
        valid = valid && priv === priv % Secp256k1::EC_ORDER_N
      end
    end
    return key
  end

  # Gets a private key from a mini-private key if the key is valid.
  #
  # Parameters:
  # * `m` (`String`): the mini-private key.
  #
  # ```
  # Secp256k1::Bitcoin.private_key_from_mini "S7qq5k98DAvee6mtQgpg4xAJatT9mR"
  # # => "53d77137b39427a35d8c4b187f532d3912e1e7135985e730633e1e3c1b87ce97"
  # ```
  #
  # Raises if the key is invalid.
  def self.private_key_from_mini(m : String)
    if mini_is_valid? m
      # The private key is just the SHA-256 hash.
      private_key = Hash.sha256_string m
      return BigInt.new private_key, 16
    else
      raise "mini private key is not valid (invalid checksum for: #{m})"
    end
    return BigInt.new "-999"
  end

  # Validates wether a mini-private key has a correct checksum and formatting.
  #
  # Parameters:
  # * `m` (`String`): the mini-private key.
  #
  # ```
  # Secp256k1::Bitcoin.mini_is_valid? "S7qq5k98DAvee6mtQgpg4xAJatT9mR"
  # # => true
  # ```
  #
  # Returns _true_ if the key contains a valid checksum and is formatted correctly.
  def self.mini_is_valid?(m : String)
    # It's only valid if it's 30 characters long and starts with a capital `S`.
    valid = m.size === 30
    valid = valid && m[0, 1] === "S"

    # It's only a valid mini-private key if the hash of `#{key}?` starts with `"00"`.
    checksum = Hash.sha256_string "#{m}?"
    valid = valid && checksum[0, 2] === "00"
    return valid
  end

  # Gets a Base-58 Wallet-Import Format (WIF) from a private key.
  #
  # Parameters:
  # * `k` (`BigInt`): the private key.
  # * `version` (`String`): the version byte, default: `"80"` (Bitcoin).
  # * `compr` (`String`): the compression byte, default: `""` (uncompressed).
  #
  # ```
  # Secp256k1::Bitcoin.wif_from_private BigInt.new("53d77137b39427a35d8c4b187f532d3912e1e7135985e730633e1e3c1b87ce97", 16)
  # # => "5JTDCfWtwBsA26NcrJJdb7xvBPvJY9jKTdppXckp3SVTrBe6pg1"
  # ```
  #
  # Note, the compression byte `compr` is either empty `""` for uncompressed keys or
  # `"01"` for compressed keys. See also `wif_from_private_compressed` and  `wif_from_private_uncompressed`.
  def self.wif_from_private(k : BigInt, version = "80", compr = "")
    # Takes the private key.
    priv = Secp256k1::Util.to_padded_hex_32 k

    # Prepends the version byte and append the compression byte.
    versioned = "#{version}#{priv}#{compr}"

    # Performs a SHA-256 hash on the extended key.
    hashed = Hash.sha256 Hash.hex_to_bin versioned

    # Performs a SHA-256 hash on the result of the SHA-256 hash.
    hashed_twice = Hash.sha256 Hash.hex_to_bin hashed

    # Takes the first four bytes of the second SHA-256 hash, this is the checksum.
    # Adds the four checksum bytes at the end of the versioned key.
    # This is the binary key.
    binary = "#{versioned}#{hashed_twice[0, 8]}"

    # Converts the result from a byte string into a Base-58 string.
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
  # Secp256k1::Bitcoin.wif_from_private_compressed BigInt.new("53d77137b39427a35d8c4b187f532d3912e1e7135985e730633e1e3c1b87ce97", 16)
  # # => "Kz2grUzxEAxNopiREbNpVbjoitAGQVXnUZY4n8pNdmWdVqub99qu"
  # ```
  def self.wif_from_private_compressed(k : BigInt, version = "80")
    # To indicate a compressed key to be used, append a `"01"` byte.
    return wif_from_private k, version, "01"
  end

  # Gets an uncompressed Base-58 Wallet-Import Format (WIF) from a private key.
  #
  # Parameters:
  # * `k` (`BigInt`): the private key
  # * `version` (`String`): the version byte, default: `"80"` (Bitcoin)
  #
  # ```
  # Secp256k1::Bitcoin.wif_from_private_uncompressed BigInt.new("53d77137b39427a35d8c4b187f532d3912e1e7135985e730633e1e3c1b87ce97", 16)
  # # => "5JTDCfWtwBsA26NcrJJdb7xvBPvJY9jKTdppXckp3SVTrBe6pg1"
  # ```
  def self.wif_from_private_uncompressed(k : BigInt, version = "80")
    # To indicate an uncompressed key to be used, don't append a compression byte.
    return wif_from_private k, version, ""
  end

  # Gets a private key from a Base-58 Wallet-Import Format (WIF).
  #
  # Parameters:
  # * `wif` (`String`): the Base-58 Wallet-Import Format (WIF).
  #
  # ```
  # Secp256k1::Bitcoin.private_key_from_wif "Kz2grUzxEAxNopiREbNpVbjoitAGQVXnUZY4n8pNdmWdVqub99qu"
  # # => "53d77137b39427a35d8c4b187f532d3912e1e7135985e730633e1e3c1b87ce97"
  # ```
  #
  # Raises if Wallet-Import Format (WIF) is invalid.
  def self.private_key_from_wif(wif : String)
    # Decodes Base-58 which contains the checksummed private key.
    checksum_key = Hash.base58_decode wif

    # The key must be 37 bytes (uncompressed) or 38 bytes (compressed).
    if checksum_key.size == 74 || checksum_key.size == 76
      # Drops the version byte, checksum, and compressed byte.
      private_key = BigInt.new checksum_key[2, 64], 16
      return Secp256k1::Util.to_padded_hex_32 private_key
    else
      raise "invalid wallet import format (invalid wif size: #{checksum_key.size})"
      return "-999"
    end
  end

  # Gets the version byte from a Base-58 Wallet-Import Format (WIF).
  #
  # Parameters:
  # * `wif` (`String`): the Base-58 Wallet-Import Format (WIF).
  #
  # ```
  # Secp256k1::Bitcoin.version_byte_from_wif "5JTDCfWtwBsA26NcrJJdb7xvBPvJY9jKTdppXckp3SVTrBe6pg1"
  # # => "80"
  # ```
  #
  # Raises if Wallet-Import Format (WIF) is invalid.
  def self.version_byte_from_wif(wif : String)
    # Decodes Base-58 which contains the checksummed private key.
    versioned = Hash.base58_decode wif

    # The key must be 37 bytes (uncompressed) or 38 bytes (compressed).
    if versioned.size === 74 || versioned.size === 76
      # Extracts the version byte.
      return versioned[0, 2]
    else
      raise "invalid wallet import format (invalid wif size: #{versioned.size})"
      return "-999"
    end
  end

  # Checks if it's a compressed or an uncompressed Wallet-Import Format (WIF).
  #
  # Parameters:
  # * `wif` (`String`): the Base-58 Wallet-Import Format (WIF).
  #
  # ```
  # Secp256k1::Bitcoin.is_wif_compressed? "5JTDCfWtwBsA26NcrJJdb7xvBPvJY9jKTdppXckp3SVTrBe6pg1"
  # # => false
  # ```
  #
  # Returns _true_ if the key is compressed.
  #
  # Raises if Wallet-Import Format (WIF) is invalid.
  def self.is_wif_compressed?(wif : String)
    # Decodes Base-58 which contains the checksummed private key.
    versioned = Hash.base58_decode wif

    # The key must be 37 bytes (uncompressed) or 38 bytes (compressed).
    if versioned.size === 74 || versioned.size === 76
      # Returns _true_ if the key is compressed.
      return versioned.size === 76
    else
      raise "invalid wallet import format (invalid wif size: #{versioned.size})"
      return "-999"
    end
  end

  # Validates wether a Wallet-Import Format (WIF) has a correct checksum and formatting.
  #
  # Parameters:
  # * `wif` (`String`): the Base-58 Wallet-Import Format (WIF).
  #
  # ```
  # Secp256k1::Bitcoin.wif_is_valid? "5JTDCfWtwBsA26NcrJJdb7xvBPvJY9jKTdppXckp3SVTrBe6pg1"
  # # => true
  # ```
  #
  # Returns _true_ if the key contains a valid checksum and is formatted correctly.
  def self.wif_is_valid?(wif : String)
    # Decodes Base-58 which contains the checksummed private key.
    checksum_key = Hash.base58_decode wif

    # The key must be 37 bytes (uncompressed) or 38 bytes (compressed).
    valid = checksum_key.size === 74 || checksum_key.size === 76

    # Only proceeds if the key is valid.
    if valid
      # Ensures the private key is valid.
      private_key = private_key_from_wif wif
      valid = valid && private_key != "-999" && private_key.size === 64

      # Drops the checksum bytes.
      versioned = checksum_key[0, 66]
      wif_checksum = checksum_key[66, 8]

      # Makes sure to honor the compression byte.
      if checksum_key.size === 76
        versioned = checksum_key[0, 68]
        wif_checksum = checksum_key[68, 8]
      end

      # Performs a SHA-256 hash on the versioned key.
      hashed = Hash.sha256 Hash.hex_to_bin versioned

      # Performs a SHA-256 hash on the result of the previous SHA-256 hash.
      hashed_twice = Hash.sha256 Hash.hex_to_bin hashed

      # Checks the WIF checksum against the private key checksum.
      pk_checksum = hashed_twice[0, 8]
      valid = valid && wif_checksum === pk_checksum
    end
    return valid
  end

  # Generates a `Bitcoin` address for any public key, compressed or uncompressed.
  #
  # Parameters:
  # * `pub` (`String`): the public key, compressed or uncompressed.
  # * `version` (`String`): the version byte, default: `"00"` (Bitcoin).
  #
  # ```
  # Secp256k1::Bitcoin.address_from_public_key "03e097fc69f0b92f711620511c07fefdd648e469df46b1e4385a00a1786f6bc55b"
  # # => "1Q1zbmPZtS2chwxpviqz6qHgoM8UUuviGN"
  # ```
  #
  # Note, compressed public keys generate compressed addresses, whereas
  # uncompressed keys generate uncompressed addresses.
  #
  # Raises if the public key is malformed.
  def self.address_from_public_key(pub : String, version = "00")
    # Ensures uncompressed or compressed public keys with prefix.
    if pub.size === 130 || pub.size === 66
      # Performs a SHA-256 hash on the public key.
      sha2 = Hash.sha256 Hash.hex_to_bin pub

      # Performs a RIPEMD-160 hash on the result of the SHA-256 hash.
      ripe = Hash.ripemd160 Hash.hex_to_bin sha2

      # Adds a version byte in front of the RIPEMD-160 hash.
      ripe_versioned = "#{version}#{ripe}"

      # Performs a SHA-256 hash on the extended RIPEMD-160 result.
      hashed = Hash.sha256 Hash.hex_to_bin ripe_versioned

      # Performs a SHA-256 hash on the result of the previous SHA-256 hash.
      hashed_twice = Hash.sha256 Hash.hex_to_bin hashed

      # Takes the first four bytes of the second SHA-256 hash; this is the address checksum.
      # Adds the four checksum bytes at the end of the extended RIPEMD-160 hash.
      # This is the 25-byte binary Bitcoin address.
      binary = "#{ripe_versioned}#{hashed_twice[0, 8]}"

      # Converts the result from a hex string into a Base-58 encoded string.
      # This is the most commonly used Bitcoin address format.
      return Hash.base58_encode binary
    else
      raise "malformed public key (invalid key size: #{pub.size})"
    end
    return "-999"
  end

  # Generates a `Bitcoin` address from an public key as `EC_Point`.
  #
  # Parameters:
  # * `p` (`EC_Point`): the public key as point with `x` and `y` coordinates.
  # * `version` (`String`): the version byte, default: `"00"` (Bitcoin).
  # * `compressed` (`Bool`): indicator if address should be compressed or not, default: `true` (compressed).
  #
  # See `address_from_public_key` and `EC_Point` for usage instructions.
  def self.address_from_public_point(p : Secp256k1::EC_Point, version = "00", compressed = true)
    # Takes the corresponding uncompressed public key.
    pub = Secp256k1::Util.public_key_uncompressed_prefix p

    # Generates a compressed address if specified.
    pub = Secp256k1::Util.public_key_compressed_prefix p if compressed
    return address_from_public_key pub, version
  end

  # Gets a `Bitcoin` address from a Base-58 Wallet-Import Format (WIF).
  #
  # Parameters:
  # * `wif` (`String`): the Base-58 Wallet-Import Format (WIF).
  #
  # ```
  # Secp256k1::Bitcoin.address_from_wif "5JTDCfWtwBsA26NcrJJdb7xvBPvJY9jKTdppXckp3SVTrBe6pg1"
  # # => "1Gbxhju13BpwpzzFRgNr2TDYCRTg94kgFC"
  # ```
  #
  # Raises if Wallet-Import Format (WIF) is invalid.
  def self.address_from_wif(wif : String)
    # Only proceeds with valid WIF provided.
    if wif_is_valid? wif
      # Gets the version byte from the WIF.
      vers = version_byte_from_wif wif
      vers = vers.to_i 16

      # The version byte of the public address is offset by `-128` (`-0x80`).
      vers -= 128

      # Makes sure the version byte is properly padded.
      vers = Secp256k1::Util.to_padded_hex_01 vers

      # Gets the private key from the WIF.
      priv = private_key_from_wif wif
      priv = BigInt.new priv, 16

      # Checks wether we want a compressed or an uncompressed address.
      comp = is_wif_compressed? wif

      return address_from_private priv, vers, comp
    else
      raise "invalid wallet import format (invalid wif: #{wif})"
      return "-999"
    end
  end

  # Generates a `Bitcoin` address from a private key.
  #
  # Parameters:
  # * `priv` (`BigInt`): the private key as number.
  # * `version` (`String`): the version byte, default: `"00"` (Bitcoin).
  # * `compressed` (`Bool`): indicator if address should be compressed or not, default: `true` (compressed).
  #
  # ```
  # Secp256k1::Bitcoin.address_from_private BigInt.new("53d77137b39427a35d8c4b187f532d3912e1e7135985e730633e1e3c1b87ce97", 16)
  # # => "1Q1zbmPZtS2chwxpviqz6qHgoM8UUuviGN"
  # ```
  def self.address_from_private(priv : BigInt, version = "00", compressed = true)
    # Having a private ECDSA key; take the corresponding public key generated with it.
    p = Secp256k1::Util.public_key_from_private priv
    return address_from_public_point p, version, compressed
  end
end
