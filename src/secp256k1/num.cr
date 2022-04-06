# Copyright 2019-2022 Afr Schoe @q9f
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

# Provides a class to conveniently handle big numbers on the elliptic
# curve. It allows to easily access decimal, hexadecimal, and binary
# representations of the numeric. In addition, it implements some
# utilities such as zpadding or asserting hexadecimal strings. It's suited
# to temporarily handle unencrypted private keys.
#
# Properties:
# * `hex` (`String`): the hexadecimal string representation of the number.
# * `dec` (`BigInt`): the decimal big-integer representation of the number.
# * `bin` (`Bytes`): the binary bytes-slice represenation of the number.
class Secp256k1::Num
  # The hexadecimal string representation of the number.
  getter hex : String
  # The decimal big-integer representation of the number.
  getter dec : BigInt
  # The binary bytes-slice represenation of the number.
  getter bin : Slice(UInt8)

  # Creates a random number using `Random::Secure` that can be used as
  # a secret (private key).
  #
  # ```
  # Num.new
  # # => #<Secp256k1::Num:0x7ff3d98013c0
  # #          @hex="568a0f505bde902db4a6afd207c794c7845fe7715da5999bb276d453c702a46d",
  # #          @dec=39142835565766237398843902819171565157710677457569850027793715608438337348717,
  # #          @bin=Bytes[86, 138, 15, 80, 91, 222, 144, 45, 180, 166, 175, 210, 7, 199, 148, 199, 132, 95, 231, 113, 93, 165, 153, 155, 178, 118, 212, 83, 199, 2, 164, 109]>
  # ```
  def initialize
    hex = "0"
    key = 0
    until key > 0 && key < N.to_big
      hex = Random::Secure.hex 32
      key = BigInt.new hex, 16
    end
    @hex = hex
    @dec = BigInt.new key
    @bin = hex.hexbytes
  end

  # Creates a number from a hexadecimal string literal.
  #
  # Parameters:
  # * `hex` (`String`): a hexadecimal string representating the number.
  #
  # ```
  # Num.new "568a0f505bde902db4a6afd207c794c7845fe7715da5999bb276d453c702a46d"
  # # => #<Secp256k1::Num:0x7fb934585480
  # #          @hex="568a0f505bde902db4a6afd207c794c7845fe7715da5999bb276d453c702a46d",
  # #          @dec=39142835565766237398843902819171565157710677457569850027793715608438337348717,
  # #          @bin=Bytes[86, 138, 15, 80, 91, 222, 144, 45, 180, 166, 175, 210, 7, 199, 148, 199, 132, 95, 231, 113, 93, 165, 153, 155, 178, 118, 212, 83, 199, 2, 164, 109]>
  # ```
  def initialize(hex : String)
    hex = assert_hexadecimal hex
    hex = "0#{hex}" if hex.size % 2 != 0
    @hex = hex
    @dec = BigInt.new hex, 16
    @bin = hex.hexbytes
  end

  # Creates a number from a big integer numeric.
  #
  # Parameters:
  # * `dec` (`BigInt`): the decimal big-integer representating the number.
  #
  # ```
  # Num.new BigInt.new "39142835565766237398843902819171565157710677457569850027793715608438337348717"
  # # => #<Secp256k1::Num:0x7fb934585480
  # #          @hex="568a0f505bde902db4a6afd207c794c7845fe7715da5999bb276d453c702a46d",
  # #          @dec=39142835565766237398843902819171565157710677457569850027793715608438337348717,
  # #          @bin=Bytes[86, 138, 15, 80, 91, 222, 144, 45, 180, 166, 175, 210, 7, 199, 148, 199, 132, 95, 231, 113, 93, 165, 153, 155, 178, 118, 212, 83, 199, 2, 164, 109]>
  # ```
  def initialize(num : BigInt)
    hex = num.to_s 16
    hex = "0#{hex}" if hex.size % 2 != 0
    @hex = hex
    @dec = num
    @bin = hex.hexbytes
  end

  # Creates a number from a binary bytes slice.
  #
  # Parameters:
  # * `bin` (`Bytes`): the binary bytes-slice represenating the number.
  #
  # ```
  # Num.new Bytes[86, 138, 15, 80, 91, 222, 144, 45, 180, 166, 175, 210, 7, 199, 148, 199, 132, 95, 231, 113, 93, 165, 153, 155, 178, 118, 212, 83, 199, 2, 164, 109]
  # # => #<Secp256k1::Num:0x7fb934585480
  # #          @hex="568a0f505bde902db4a6afd207c794c7845fe7715da5999bb276d453c702a46d",
  # #          @dec=39142835565766237398843902819171565157710677457569850027793715608438337348717,
  # #          @bin=Bytes[86, 138, 15, 80, 91, 222, 144, 45, 180, 166, 175, 210, 7, 199, 148, 199, 132, 95, 231, 113, 93, 165, 153, 155, 178, 118, 212, 83, 199, 2, 164, 109]>
  # ```
  def initialize(bin : Slice(UInt8))
    @hex = bin.hexstring
    @dec = BigInt.new bin.hexstring, 16
    @bin = bin
  end

  # Returns an unprefixed hexadecimal string representation.
  #
  # ```
  # Num.new(Bytes[137]).to_hex
  # # => "89"
  # ```
  def to_hex : String
    @hex
  end

  # Returns an `0x`-prefixed hexadecimal string representation.
  #
  # ```
  # Num.new(Bytes[137]).to_prefixed_hex
  # # => "0x89"
  # ```
  def to_prefixed_hex : String
    "0x#{@hex}"
  end

  # Returns a z-padded hexadecimal string representation.
  #
  # Parameters:
  # * `length` (`Int`): the byte-size of the final z-padded hex-string (default `32`).
  #
  # ```
  # Num.new(Bytes[137]).to_zpadded_hex
  # # => "0000000000000000000000000000000000000000000000000000000000000089"
  # ```
  def to_zpadded_hex(length = 32) : String
    zpadded_hex = @hex
    while zpadded_hex.size < length * 2
      zpadded_hex = "0#{zpadded_hex}"
    end
    zpadded_hex
  end

  # Returns a big-integer representation of the number.
  #
  # ```
  # Num.new(Bytes[137]).to_big
  # # => 137
  # ```
  def to_big : BigInt
    @dec
  end

  # Returns a binary byte-slice representation of the number.
  #
  # ```
  # Num.new("0x89").to_bytes
  # # => Bytes[137]
  # ```
  def to_bytes : Bytes
    @bin
  end

  # Returns a z-padded byte-slice binary representation.
  #
  # Parameters:
  # * `length` (`Int`): the byte-size of the final z-padded slice (default `32`).
  #
  # ```
  # Num.new(Bytes[137]).to_zpadded_bytes
  # # => Bytes[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 137]
  # ```
  def to_zpadded_bytes(length = 32) : Bytes
    zpadded_bytes = @bin
    while zpadded_bytes.size < length
      zpadded_bytes = Util.concat_bytes Bytes[0x00], zpadded_bytes
    end
    zpadded_bytes
  end

  # Assists to determine wether a hex-string is prefixed.
  private def is_prefixed?(hex : String) : Bool
    prefix_match = /\A0x/.match hex
    unless prefix_match.nil?
      return true
    else
      return false
    end
  end

  # Assists to remove a `0x`-hex prefix.
  private def remove_prefix(hex : String) : String
    if is_prefixed? hex
      return hex[2..-1]
    else
      return hex
    end
  end

  # Assists to assert wether a `String` is hexadecimal or not.
  private def assert_hexadecimal(hex : String) : String
    if is_prefixed? hex
      hex = remove_prefix hex
    end
    hex_match = /\A[0-9a-fA-F]*\z/.match hex
    unless hex_match.nil?
      return hex_match.string
    else
      raise "Invalid hex data provided: '#{hex}'"
    end
  end
end
