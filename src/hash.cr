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

require "openssl"
require "sha3"

# The `Secp256k1::Hash` module wraps various hashing functions for convenience
# and exposes them for general use.
module Secp256k1::Hash
  # The Base-58 alphabet for `Bitcoin` addresses is a Base-64 alphabet without
  # `0`, `O`, `I`, and `l` to omit similar-looking letters.
  BASE_58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

  # The Base-56 alphabet for `Bitcoin` mini-private keys is a Base-58 alphabet
  # without `1` and `o` to additionally omit more similar-looking letters.
  BASE_56 = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz"

  # Operating a SHA3-256 hash on a byte array.
  #
  # Parameters:
  # * `b` (`Bytes`): the byte array to be hashed.
  #
  # ```
  # Secp256k1::Hash.sha3 Bytes[183, 149, 205, 44, 92, 224, 204, 99, 44, 161, 246, 94, 146, 27, 156, 117, 27, 54, 62, 151, 252, 174, 236, 129, 192, 42, 133, 183, 99, 68, 130, 104]
  # # => "66bb65180108362a3e25ba8282f7b96bfe840ce34a2e5dbc421aa8a590cc5f2e"
  # ```
  def self.sha3(b : Bytes)
    sha3 = Digest::SHA3.new(256)
    sha3.update(b).hexdigest
  end

  # Operating a SHA3-256 hash on an actual string literal.
  #
  # Parameters:
  # * `h` (`String`): the string literal to be hashed.
  #
  # ```
  # Secp256k1::Hash.sha3 "b795cd2c5ce0cc632ca1f65e921b9c751b363e97fcaeec81c02a85b763448268"
  # # => "aedc012933679615eb93fb0063f53010e6f0034e92aaccf97dacc46e338037e9"
  # ```
  def self.sha3(h : String)
    sha3 = Digest::SHA3.new(256)
    sha3.update(h).hexdigest
  end

  # Operating a Keccak-256 hash on a byte array.
  #
  # Parameters:
  # * `b` (`Bytes`): the byte array to be hashed.
  #
  # ```
  # Secp256k1::Hash.keccak256 Bytes[183, 149, 205, 44, 92, 224, 204, 99, 44, 161, 246, 94, 146, 27, 156, 117, 27, 54, 62, 151, 252, 174, 236, 129, 192, 42, 133, 183, 99, 68, 130, 104]
  # # => "fcb41efa0456ba9f27e573422d6b5898c61da6f2137d07e4dae618eddd72e003"
  # ```
  def self.keccak256(b : Bytes)
    keccak = Digest::Keccak3.new(256)
    keccak.update(b).hexdigest
  end

  # Operating a Keccak-256 hash on an actual string literal.
  #
  # Parameters:
  # * `h` (`String`): the string literal to be hashed.
  #
  # ```
  # Secp256k1::Hash.keccak256 "b795cd2c5ce0cc632ca1f65e921b9c751b363e97fcaeec81c02a85b763448268"
  # # => "99cfa79866ec88f87f8e25a98a4b9873f3f8ee82482a317a5494572b00f51cec"
  # ```
  def self.keccak256(h : String)
    keccak = Digest::Keccak3.new(256)
    keccak.update(h).hexdigest
  end

  # Operating a SHA2-256 hash on a byte array.
  #
  # Parameters:
  # * `b` (`Bytes`): the byte array to be hashed.
  #
  # ```
  # Secp256k1::Hash.sha256 Bytes[183, 149, 205, 44, 92, 224, 204, 99, 44, 161, 246, 94, 146, 27, 156, 117, 27, 54, 62, 151, 252, 174, 236, 129, 192, 42, 133, 183, 99, 68, 130, 104]
  # # => "2739cc5f45c0e05236527e4e687dc54f0d5e88be64b9a90e5264a6721c0c71f2"
  # ```
  def self.sha256(b : Bytes)
    OpenSSL::Digest.new("SHA256").update(b).final.hexstring
  end

  # Operating a SHA2-256 hash on an actual string literal.
  #
  # Parameters:
  # * `h` (`String`): the string literal to be hashed.
  #
  # ```
  # Secp256k1::Hash.sha256 "b795cd2c5ce0cc632ca1f65e921b9c751b363e97fcaeec81c02a85b763448268"
  # # => "452a41c28c9981faebb402095a5d553de28dc212338057aed27081110dfb907a"
  # ```
  def self.sha256(h : String)
    OpenSSL::Digest.new("SHA256").update(h).final.hexstring
  end

  # Operating a SHA2-512 hash on a byte array.
  #
  # Parameters:
  # * `b` (`Bytes`): the byte array to be hashed.
  #
  # ```
  # Secp256k1::Hash.sha512 Bytes[183, 149, 205, 44, 92, 224, 204, 99, 44, 161, 246, 94, 146, 27, 156, 117, 27, 54, 62, 151, 252, 174, 236, 129, 192, 42, 133, 183, 99, 68, 130, 104]
  # # => "c3c4dd794c193fa9cd08ebb2f9ffd42cd10bc7a7ccc07b3b02aab3a5fa142e296a423504c72957ed2d228e29d03a2f0478a2f9a3fd8d8331a653628b3eebb0b9"
  # ```
  def self.sha512(b : Bytes)
    return OpenSSL::Digest.new("SHA512").update(b).hexdigest
  end

  # Operating a SHA2-512 hash on an actual string literal.
  #
  # Parameters:
  # * `h` (`String`): the string literal to be hashed.
  #
  # ```
  # Secp256k1::Hash.sha512_string ""
  # # => "90a8166a2dd1a8014d4c1f13ead5ce651ff4f86b5b47b70e5d78d401f65374d12eb3436ac624a9313b86f461beded0f5e9272eb7930ad8c680fb0af40cb59b99"
  # ```
  def self.sha512_string(h : String)
    return OpenSSL::Digest.new("SHA512").update(h).hexdigest
  end

  # Operating a RIPEMD-160 hash on a byte array.
  #
  # Parameters:
  # * `b` (`Bytes`): the byte array to be hashed.
  #
  # ```
  # Secp256k1::Hash.ripemd160 Bytes[183, 149, 205, 44, 92, 224, 204, 99, 44, 161, 246, 94, 146, 27, 156, 117, 27, 54, 62, 151, 252, 174, 236, 129, 192, 42, 133, 183, 99, 68, 130, 104]
  # # => "5f3455f9ac58e25be08c99a7090108751b4796b9"
  # ```
  def self.ripemd160(b : Bytes)
    OpenSSL::Digest.new("RIPEMD160").update(b).final.hexstring
  end

  # Operating a RIPEMD-160 hash on an actual string literal.
  #
  # Parameters:
  # * `h` (`String`): the string literal to be hashed.
  #
  # ```
  # Secp256k1::Hash.ripemd160 "b795cd2c5ce0cc632ca1f65e921b9c751b363e97fcaeec81c02a85b763448268"
  # # => "46dff6cd5666c8e67db26ac0dfaf685bf71fc5f6"
  # ```
  def self.ripemd160(h : String)
    OpenSSL::Digest.new("RIPEMD160").update(h).final.hexstring
  end

  # Decodes a hexadecimal string from a Base-58 encoded string.
  #
  # Parameters:
  # * `s` (`String`): The Base-58 encoded string to be decoded.
  #
  # ```
  # Secp256k1::Hash.base58_decode "1CSSfnxKnQK1GDWSaWqNpYXSdfPTtSooHt"
  # # => "007d7935bde6c9341de87a4d64588783033e23472d7322c46b"
  # ```
  def self.base58_decode(s : String)
    # Cycle through each character of string.
    index = 0
    decimal = BigInt.new 0
    while index < s.size
      b58_char = s[index]
      position = BASE_58.index(b58_char)
      if !position.nil?
        decimal = decimal * 58 + position
        index += 1
      else
        raise "cannot decode, invalid base58 character: '#{s[index]}'"
      end
    end

    # Count leading `1`s and pad with `"00"` bytes.
    hex = decimal.to_s 16
    leading = 0
    while s[leading] === '1'
      leading += 1
      hex = "00#{hex}"
    end
    hex
  end

  # Encodes a Base-58 string from a hexadecimal string.
  #
  # Parameters:
  # * `h` (`String`): The hexadecimal string to be encoded.
  #
  # ```
  # Secp256k1::Hash.base58_encode "007d7935bde6c9341de87a4d64588783033e23472d7322c46b"
  # # => "1CSSfnxKnQK1GDWSaWqNpYXSdfPTtSooHt"
  # ```
  def self.base58_encode(h : String)
    # Do a Base-58 mapping for the hash.
    pub = BigInt.new h, 16
    adr = String.new
    while pub > 0
      pub, rem = pub.divmod 58
      adr += base58_char rem.to_i
    end

    # Replace leading zero bytes with `1`.
    i, s = 0, 2
    current_byte = h[i, s]
    while current_byte.to_i(16) === 0
      adr = "#{adr}1"
      i += s
      current_byte = h[i, s]
    end

    # Reverse because we did the entire conversion backwards.
    adr.reverse
  end

  # Gets a character from the Base-56 alphabet at position `i`.
  #
  # Parameters:
  # * `i` (`Int32`): the position in the Base-56 alphabet.
  #
  # ```
  # Secp256k1::Hash.base56_char 13
  # # => 'F'
  # ```
  def self.base56_char(i : Int32)
    i = i % 56
    BASE_56[i]
  end

  # Gets a character from the Base-58 alphabet at position `i`.
  #
  # Parameters:
  # * `i` (`Int32`): the position in the Base-58 alphabet.
  #
  # ```
  # Secp256k1::Hash.base58_char 13
  # # => 'E'
  # ```
  def self.base58_char(i : Int32)
    i = i % 58
    BASE_58[i]
  end

  # Helper function to convert byte arrays to hexadecimal strings.
  #
  # Parameters:
  # * `b` (`Bytes`): the byte array to be converted.
  #
  # ```
  # Secp256k1::Hash.bin_to_hex Bytes[183, 149, 205, 44, 92, 224, 204, 99, 44, 161, 246, 94, 146, 27, 156, 117, 27, 54, 62, 151, 252, 174, 236, 129, 192, 42, 133, 183, 99, 68, 130, 104]
  # => "b795cd2c5ce0cc632ca1f65e921b9c751b363e97fcaeec81c02a85b763448268"
  # ```
  def self.bin_to_hex(b : Bytes)
    b.hexstring
  end

  # Helper function to convert hexadecimal strings to byte arrays.
  #
  # Parameters:
  # * `h` (`String`): the hexadecimal string to be converted.
  #
  # ```
  # Secp256k1::Hash.hex_to_bin "b795cd2c5ce0cc632ca1f65e921b9c751b363e97fcaeec81c02a85b763448268"
  # => Bytes[183, 149, 205, 44, 92, 224, 204, 99, 44, 161, 246, 94, 146, 27, 156, 117, 27, 54, 62, 151, 252, 174, 236, 129, 192, 42, 133, 183, 99, 68, 130, 104]
  # ```
  def self.hex_to_bin(h : String)
    h.hexbytes
  end
end
