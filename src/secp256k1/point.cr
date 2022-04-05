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

@[Link("gmp")]
lib LibGMP
  fun mpz_powm_sec = __gmpz_powm_sec(rop : MPZ*, base : MPZ*, exp : MPZ*, mod : MPZ*)
end

class Secp256k1::Point
  property x : Num
  property y : Num

  def initialize(x : Num, y : Num)
    @x = x
    @y = y
  end

  def initialize(priv : Num)
    pub = Curve.mul G, priv.to_big
    @x = pub.x
    @y = pub.y
  end

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

  def uncompressed
    prefix = "04"
    "#{prefix}#{@x.to_zpadded_hex}#{@y.to_zpadded_hex}"
  end

  def compressed
    prefix = 2 + @y.to_big % 2
    prefix = "0#{prefix}"
    "#{prefix}#{@x.to_zpadded_hex}"
  end
end
