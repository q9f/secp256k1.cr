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


# Implements 256-bit Secp256k1 Koblitz elliptic curve.
# Ref: [secg.org/sec2-v2.pdf](https://www.secg.org/sec2-v2.pdf)
# 
# Secp256k1 has the characteristic p, it is defined over the prime field ℤ_p.
# Ref: [en.bitcoin.it/wiki/Secp256k1](https://en.bitcoin.it/wiki/Secp256k1)
module Secp256k1::Core
  # elliptic curve modular multiplicative inverse of a
  def self.ec_mod_inv(a : BigInt, prime = EC_PRIME_P)
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

    return m_low % prime
  end

  # elliptic curve jive addition of point p(x, y) and q(x, y).
  # 'draw' a line between p and q which will intersect the
  # curve in the point r which will be mirrored over the x-axis.
  def self.ec_add(p : EC_Point, q : EC_Point, prime = EC_PRIME_P)
    x_delta = q.x - p.x
    x_inv = ec_mod_inv x_delta
    y_delta = q.y - p.y
    m = (y_delta * x_inv) % prime
    x = (m * m - p.x - q.x) % prime
    y = (m * (p.x - x) - p.y) % prime
    x = BigInt.new x
    y = BigInt.new y
    return EC_Point.new x, y
  end

  # elliptic curve juke point doubling of p(x, y).
  # a special case of addition where both points are the same.
  # 'draw' a tangent line at p which will intersect the curve
  # at point r which will be mirrored over the x-axis.
  def self.ec_double(p : EC_Point, prime = EC_PRIME_P)
    lam_numer = 3 * p.x * p.x + EC_FACTOR_A
    lam_denom = 2 * p.y
    lam_inv = ec_mod_inv lam_denom
    lam = (lam_numer * lam_inv) % prime
    x = (lam * lam - 2 * p.x) % prime
    y = (lam * (p.x - x) - p.y) % prime
    x = BigInt.new x
    y = BigInt.new y
    return EC_Point.new x, y
  end

  # elliptic curve sequence multiplication of point p(x, y) and
  # a skalar s, with s being a private key within the elliptic
  # curve field size of EC_ORDER_N
  def self.ec_mul(p : EC_Point, s : BigInt)
    # catch skalars outside of the ec field size and exit
    if s === 0 || s >= EC_ORDER_N
      raise "invalid private key: outside of ec field size."
      exit 1
    end
    s_bin = s.to_s 2
    q = p
    s_bin.each_char_with_index do |char, index|
      next if index === 0
      q = ec_double q
      if char === '1'
        q = ec_add q, p
      end
    end
    return q
  end
end
