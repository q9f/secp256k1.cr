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

class Secp256k1::Num
  property hex : String
  property dec : BigInt
  property bin : Slice(UInt8)

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

  def initialize(hex : String)
    hex = assert_hexadecimal hex
    hex = "0#{hex}" if hex.size % 2 != 0
    @hex = hex
    @dec = BigInt.new hex, 16
    @bin = hex.hexbytes
  end

  def initialize(num : BigInt)
    hex = num.to_s 16
    hex = "0#{hex}" if hex.size % 2 != 0
    @hex = hex
    @dec = num
    @bin = hex.hexbytes
  end

  def initialize(bin : Slice(UInt8))
    @hex = bin.hexstring
    @dec = BigInt.new bin.hexstring, 16
    @bin = bin
  end

  def to_hex
    @hex
  end

  def to_prefixed_hex
    "0x#{@hex}"
  end

  def to_zpadded_hex(length = 32)
    zpadded_hex = @hex
    while zpadded_hex.size < length * 2
      zpadded_hex = "0#{zpadded_hex}"
    end
    zpadded_hex
  end

  def to_big
    @dec
  end

  def to_bytes
    @bin
  end

  def to_zpadded_bytes(length = 32)
    zpadded_bytes = @bin
    byte_zero = Bytes[0]
    while zpadded_bytes.size < length
      slice_size = zpadded_bytes.size + 1
      zpadded_slice = Slice(UInt8).new slice_size
      slice_pointer = zpadded_slice.to_unsafe
      byte_zero.copy_to(slice_pointer, 0)
      slice_pointer += 1
      zpadded_bytes.copy_to(slice_pointer, zpadded_bytes.size)
      zpadded_bytes = zpadded_slice
    end
    zpadded_bytes
  end

  private def is_prefixed?(hex : String)
    prefix_match = /\A0x/.match hex
    unless prefix_match.nil?
      return true
    else
      return false
    end
  end

  private def remove_prefix(hex : String)
    if is_prefixed? hex
      return hex[2..-1]
    else
      return hex
    end
  end

  private def assert_hexadecimal(hex : String)
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
