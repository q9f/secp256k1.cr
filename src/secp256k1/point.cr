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

# Links GMP to directly leverage integer exponentiation.
#
# Ref: https://github.com/crystal-lang/crystal/issues/8612
@[Link("gmp")]
lib LibGMP
  fun mpz_powm_sec = __gmpz_powm_sec(rop : MPZ*, base : MPZ*, exp : MPZ*, mod : MPZ*)
end

# Provides a point in the two-dimensional space of any elliptic curve.
#
# Properties:
# * `x` (`Num`): the position on the x-axis.
# * `y` (`Num`): the position on the y-axis.
class Secp256k1::Point
  # The position on the x-axis.
  property x : Num

  # The position on the y-axis.
  property y : Num

  # Provides a public point in the two-dimensional space on the given
  # elliptic curve by passing the x- and y-coordinates (public key).
  #
  # Parameters:
  # * `x` (`Num`): the position on the x-axis.
  # * `y` (`Num`): the position on the y-axis.
  #
  # ```
  # x = Num.new "efc4f8d8bfc778463e4d4916d88bf3f057e6dc96cb2adc26dfb91959c4bef4a5"
  # y = Num.new "cecd9a83fefafcb3cf99fde0c340bbe2fed9cdd0d25b53f4e08254acefb69ae0"
  # Point.new x, y
  # # => #<Secp256k1::Point:0x7f47952e6f00
  # #          @x=#<Secp256k1::Num:0x7f47952e9480
  # #              @hex="efc4f8d8bfc778463e4d4916d88bf3f057e6dc96cb2adc26dfb91959c4bef4a5",
  # #              @dec=108450790312736419148091503336190989867379581793003243037811027177541631669413,
  # #              @bin=Bytes[239, 196, 248, 216, 191, 199, 120, 70, 62, 77, 73, 22, 216, 139, 243, 240, 87, 230, 220, 150, 203, 42, 220, 38, 223, 185, 25, 89, 196, 190, 244, 165]>,
  # #          @y=#<Secp256k1::Num:0x7f47952e93c0
  # #              @hex="cecd9a83fefafcb3cf99fde0c340bbe2fed9cdd0d25b53f4e08254acefb69ae0",
  # #              @dec=93539716883975436131751270446270238300906572229893209404647676230869395610336,
  # #              @bin=Bytes[206, 205, 154, 131, 254, 250, 252, 179, 207, 153, 253, 224, 195, 64, 187, 226, 254, 217, 205, 208, 210, 91, 83, 244, 224, 130, 84, 172, 239, 182, 154, 224]>>
  # ```
  def initialize(x : Num, y : Num)
    @x = x
    @y = y
  end

  # Provides a public point in the two-dimensional space on the given
  # elliptic curve by passing a random number (private key).
  #
  # Parameters:
  # * `priv` (`Num`): the random number giving access to the point.
  #
  # ```
  # priv = Num.new "e50932676c9901f259659d62f0c56fd899feca3f57ecab147a5ef8a0b59defc3"
  # Point.new priv
  # # => #<Secp256k1::Point:0x7f7377407ee0
  # #          @x=#<Secp256k1::Num:0x7f736e341b00
  # #              @hex="aff8674d6b96a6c58dbab08b903565363271308888340a2caddf88e56165930f",
  # #              @dec=79593639541256659698952500103746656102855706770414568473917856266058507588367,
  # #              @bin=Bytes[175, 248, 103, 77, 107, 150, 166, 197, 141, 186, 176, 139, 144, 53, 101, 54, 50, 113, 48, 136, 136, 52, 10, 44, 173, 223, 136, 229, 97, 101, 147, 15]>,
  # #          @y=#<Secp256k1::Num:0x7f736e341ac0
  # #              @hex="21f4c49cfe90da39c254a51b8ee8afcdd8c02dd566f13582c23e104c7ed5936b",
  # #              @dec=15358791661898278541670676806913272995387450360720708081975214114817468371819,
  # #              @bin=Bytes[33, 244, 196, 156, 254, 144, 218, 57, 194, 84, 165, 27, 142, 232, 175, 205, 216, 192, 45, 213, 102, 241, 53, 130, 194, 62, 16, 76, 126, 213, 147, 107]>>
  # ```
  def initialize(priv : Num)
    pub = Curve.mul G, priv.to_big
    @x = pub.x
    @y = pub.y
  end

  # Provides a public point in the two-dimensional space on the given
  # elliptic curve by passing a compressed or uncompressed public key.
  #
  # Parameters:
  # * `pub` (`String`): the public key string (compressed or uncompressed).
  #
  # ```
  # pub = "03aff8674d6b96a6c58dbab08b903565363271308888340a2caddf88e56165930f"
  # Point.new pub
  # # => #<Secp256k1::Point:0x7f3b1b9aaf00
  # #          @x=#<Secp256k1::Num:0x7f3b1b9ad380
  # #              @hex="aff8674d6b96a6c58dbab08b903565363271308888340a2caddf88e56165930f",
  # #              @dec=79593639541256659698952500103746656102855706770414568473917856266058507588367,
  # #              @bin=Bytes[175, 248, 103, 77, 107, 150, 166, 197, 141, 186, 176, 139, 144, 53, 101, 54, 50, 113, 48, 136, 136, 52, 10, 44, 173, 223, 136, 229, 97, 101, 147, 15]>,
  # #          @y=#<Secp256k1::Num:0x7f3b1b9ad340
  # #              @hex="21f4c49cfe90da39c254a51b8ee8afcdd8c02dd566f13582c23e104c7ed5936b",
  # #              @dec=15358791661898278541670676806913272995387450360720708081975214114817468371819,
  # #              @bin=Bytes[33, 244, 196, 156, 254, 144, 218, 57, 194, 84, 165, 27, 142, 232, 175, 205, 216, 192, 45, 213, 102, 241, 53, 130, 194, 62, 16, 76, 126, 213, 147, 107]>>
  # ```
  def initialize(pub : String)
    case pub.size
    when 130, 128
      pub = pub[2, 128] if pub.size === 130
      @x = Num.new pub[0, 64]
      @y = Num.new pub[64, 64]
    when 66
      prefix = pub[0, 2]
      if prefix === "02" || prefix === "03"
        prime = P.to_big
        x = Num.new(pub[2, 64]).to_big

        a = x ** 3 % prime
        a = (a + 7) % prime
        e = ((prime + 1) // 4) % prime
        y = BigInt.new
        LibGMP.mpz_powm_sec(y, a, e, prime)

        y_parity = prefix.to_i - 2
        y = -y % prime if y % 2 != y_parity

        @x = Num.new x
        @y = Num.new y
      else
        raise "Invalid prefix for compressed public point: #{prefix}"
      end
    else
      raise "Unknown public point format (Invalid size: #{pub.size})"
    end
  end

  # Returns a prefixed, uncompressed public key string for th given point
  # in the format `04|x|y`.
  #
  # ```
  # priv = Num.new "e50932676c9901f259659d62f0c56fd899feca3f57ecab147a5ef8a0b59defc3"
  # Point.new(priv).uncompressed
  # # => "04aff8674d6b96a6c58dbab08b903565363271308888340a2caddf88e56165930f21f4c49cfe90da39c254a51b8ee8afcdd8c02dd566f13582c23e104c7ed5936b"
  # ```
  def uncompressed
    prefix = "04"
    "#{prefix}#{@x.to_zpadded_hex}#{@y.to_zpadded_hex}"
  end

  # Returns a prefixed, compressed public key string for th given point
  # in the format `prefix|x|y`.
  #
  # ```
  # priv = Num.new "e50932676c9901f259659d62f0c56fd899feca3f57ecab147a5ef8a0b59defc3"
  # Point.new(priv).compressed
  # # => "03aff8674d6b96a6c58dbab08b903565363271308888340a2caddf88e56165930f"
  # ```
  def compressed
    prefix = 2 + @y.to_big % 2
    prefix = "0#{prefix}"
    "#{prefix}#{@x.to_zpadded_hex}"
  end
end
