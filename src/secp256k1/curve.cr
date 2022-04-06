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

# Implements 256-bit `Secp256k1` Koblitz elliptic curve operations.
#
# Ref: [secg.org/sec2-v2.pdf](https://www.secg.org/sec2-v2.pdf)
module Secp256k1::Curve
  extend self

  # Computes the elliptic curve modular multiplicative inverse of `a`.
  #
  # Paremeters:
  # * `a` (`Num | BigInt`): the integer that we want the modular inverse of.
  # * `prime` (`Num`): the prime number that shapes the field (default `P`).
  #
  # Returns a `Num` containing the mod inverse.
  #
  # ```
  # a = Num.new "ea678c668356d16d8bf5c69f95c1055e39bd24174605f64846e27c3ae6a88d81"
  # Curve.mod_inv a
  # # => #<Secp256k1::Num:0x7fe839493480
  # #          @hex="2901bbb12fcb64e9887e699e69e6b0b3811db18f6b4f94dfb26084e5cb38cac7",
  # #          @dec=18547889042489459453149555262266367802647896593999507743600711803155665963719,
  # #          @bin=Bytes[41, 1, 187, 177, 47, 203, 100, 233, 136, 126, 105, 158, 105, 230, 176, 179, 129, 29, 177, 143, 107, 79, 148, 223, 178, 96, 132, 229, 203, 56, 202, 199]>
  # ```
  def mod_inv(a : Num | BigInt, prime = P) : Num
    a = a.to_big if a.is_a? Num
    prime = prime.to_big if prime.is_a? Num
    m_low = 1
    m_high = 0
    v_low = a % prime
    v_high = prime
    while v_low > 1
      v_ratio = v_high // v_low
      m_low_r = m_low * v_ratio
      v_low_r = v_low * v_ratio
      m = m_high - m_low_r
      v = v_high - v_low_r
      m_high = m_low
      v_high = v_low
      m_low = m
      v_low = v
    end
    Num.new m_low % prime
  end

  # Computes the elliptic curve jive addition of point `p(x, y)` and `q(x, y)`.
  # It _draws_ a line between `p` and `q` which will intersect the
  # curve in the point `r` which will be mirrored over the `x`-axis.
  #
  # Paramters:
  # * `p` (`Num`): the point `p(x, y)` to be used in the jive addition.
  # * `q` (`Num`): the point `q(x, y)` to be used in the jive addition.
  # * `prime` (`Num`): the prime number that shapes the field (default `P`).
  #
  # Returns a `Point` containing the result of the intersection.
  # ```
  # p = Point.new Num.new "5cb1eec17e38b004a8fd90fa8e423432430f60d76c30bb33f4091243c029e86d"
  # q = Point.new Num.new "7e17f60baa7b8dc8581a55f7be1ea263c6a88452cf3f0a3f710651767654946c"
  # Curve.add p, q
  # # => #<Secp256k1::Point:0x7f9cb270f5e0
  # #          @x=#<Secp256k1::Num:0x7f9cb26e8580
  # #              @hex="462691876380f2b744fbeaac38c69b61f6fc0c09c88161d95a6c121ff939a62b",
  # #              @dec=31730043992582273538171659139596419882010265215932424156945250658252958049835,
  # #              @bin=Bytes[70, 38, 145, 135, 99, 128, 242, 183, 68, 251, 234, 172, 56, 198, 155, 97, 246, 252, 12, 9, 200, 129, 97, 217, 90, 108, 18, 31, 249, 57, 166, 43]>,
  # #          @y=#<Secp256k1::Num:0x7f9cb26e8540
  # #              @hex="5ab931d6727872d33ea0491705680f5fbcb7409ba80541470673c4fce4dfeea4",
  # #              @dec=41035367046532706466310839850976742216202985567094126989716802462994340507300,
  # #              @bin=Bytes[90, 185, 49, 214, 114, 120, 114, 211, 62, 160, 73, 23, 5, 104, 15, 95, 188, 183, 64, 155, 168, 5, 65, 71, 6, 115, 196, 252, 228, 223, 238, 164]>>
  # ```
  def add(p : Point, q : Point, prime = P) : Point
    prime = prime.to_big if prime.is_a? Num
    p_x = p.x.to_big
    p_y = p.y.to_big
    q_x = q.x.to_big
    q_y = q.y.to_big
    x_delta = q_x - p_x
    x_inv = mod_inv x_delta
    y_delta = q_y - p_y
    m = (y_delta * x_inv.to_big) % prime
    x = (m * m - p_x - q_x) % prime
    y = (m * (p_x - x) - p_y) % prime
    x = Num.new x
    y = Num.new y
    Point.new x, y
  end

  # Computes the elliptic curve juke point doubling of `p(x, y)`.
  # This is a special case of addition where both points are the same.
  # It _draws_ a tangent line at `p` which will intersect the curve
  # at point `r` which will be mirrored over the `x`-axis.
  #
  # Paramters:
  # * `p` (`Point`): the point `p(x, y)` to be used in the juke doubling.
  # * `prime` (`Num`): the prime number that shapes the field (default `P`).
  #
  # Returns a `Point` as a result of the intersection.
  #
  # ```
  # p = Point.new Num.new "5cb1eec17e38b004a8fd90fa8e423432430f60d76c30bb33f4091243c029e86d"
  # Curve.double p
  # # => #<Secp256k1::Point:0x7f58a244e860
  # #          @x=#<Secp256k1::Num:0x7f58a240fdc0
  # #              @hex="a4a5f515981b6375a8f95c60607ca5ad5fee99bfc1615dabc9340f67e71bbfd0",
  # #              @dec=74472528443376700120710890798997658581940283975604946405194317381666873262032,
  # #              @bin=Bytes[164, 165, 245, 21, 152, 27, 99, 117, 168, 249, 92, 96, 96, 124, 165, 173, 95, 238, 153, 191, 193, 97, 93, 171, 201, 52, 15, 103, 231, 27, 191, 208]>,
  # #          @y=#<Secp256k1::Num:0x7f58a240fd80
  # #              @hex="0fa62813ae49d71dd3a19fbd17516e7e9dcdd5753d69cb13d87051d8d327253c",
  # #              @dec=7078265941949780810129057229376739925018916922271301049726817038887681467708,
  # #              @bin=Bytes[15, 166, 40, 19, 174, 73, 215, 29, 211, 161, 159, 189, 23, 81, 110, 126, 157, 205, 213, 117, 61, 105, 203, 19, 216, 112, 81, 216, 211, 39, 37, 60]>>
  # ```
  def double(p : Point, prime = P) : Point
    prime = prime.to_big if prime.is_a? Num
    p_x = p.x.to_big
    p_y = p.y.to_big
    lam_numer = 3 * p_x * p_x
    lam_denom = 2 * p_y
    lam_inv = mod_inv Num.new lam_denom
    lam = (lam_numer * lam_inv.to_big) % prime
    x = (lam * lam - 2 * p_x) % prime
    y = (lam * (p_x - x) - p_y) % prime
    x = Num.new x
    y = Num.new y
    Point.new x, y
  end

  # Computes the elliptic curve sequence multiplication of point `p(x, y)`
  # and a skalar `s`; with `s` being a private key within the elliptic
  # curve field size of `N`.
  #
  # Paramters:
  # * `p` (`Point`): the point `p(x, y)` to be used in the sequencing.
  # * `s` (`Num | BigInt`): a skalar, in most cases a private key.
  #
  # Returns a `Point` as a result of the multiplication.
  #
  # ```
  # p = Point.new Num.new "5cb1eec17e38b004a8fd90fa8e423432430f60d76c30bb33f4091243c029e86d"
  # s = Num.new "f51ad125548b7a283ebf15ab830a25c850d4d863078c48cc9993b79ee18ee11e"
  # Curve.mul p, s
  # # => #<Secp256k1::Point:0x7f4b6f6da940
  # #          @x=#<Secp256k1::Num:0x7f4b6f6cef00
  # #              @hex="748f267620fa2cbf67c925db79a9bef6f9025e642d9c15c1d34b4961471636b5",
  # #              @dec=52721215017030004050607035413180757873535914286730888523429593251155658815157,
  # #              @bin=Bytes[116, 143, 38, 118, 32, 250, 44, 191, 103, 201, 37, 219, 121, 169, 190, 246, 249, 2, 94, 100, 45, 156, 21, 193, 211, 75, 73, 97, 71, 22, 54, 181]>,
  # #          @y=#<Secp256k1::Num:0x7f4b6f6cee00
  # #              @hex="73832331979d89d395912061e341f8468cfb3e619da06a057e4a5ca95bb95e77",
  # #              @dec=52247677450688090944696492452353217603423545532791062178926183551888078233207,
  # #              @bin=Bytes[115, 131, 35, 49, 151, 157, 137, 211, 149, 145, 32, 97, 227, 65, 248, 70, 140, 251, 62, 97, 157, 160, 106, 5, 126, 74, 92, 169, 91, 185, 94, 119]>>
  # ```
  def mul(p : Point, s : Num | BigInt) : Point
    s = s.to_big if s.is_a? Num
    if s === 0 || s >= N.to_big
      raise "Invalid scalar: outside of Secp256k1 field dimension."
    end
    s_bin = s.to_s 2
    q = p
    s_bin.each_char_with_index do |char, index|
      next if index === 0
      q = double q
      if char === '1'
        q = add q, p
      end
    end
    q
  end
end
