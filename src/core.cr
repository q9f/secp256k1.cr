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

# Implements 256-bit `Secp256k1` Koblitz elliptic curve.
# Ref: [secg.org/sec2-v2.pdf](https://www.secg.org/sec2-v2.pdf)
#
# `Secp256k1` has the characteristic prime `p`, it is defined over the prime field ℤ_p.
# Ref: [en.bitcoin.it/wiki/Secp256k1](https://en.bitcoin.it/wiki/Secp256k1)
module Secp256k1::Core
  # Computes the elliptic curve modular multiplicative inverse of `a`.
  #
  # Paremeters:
  # * `a` (`BigInt`): the integer that we want the modular inverse of.
  # * `prime` (`BigInt`): the prime number that shapes the field, default: `EC_PRIME_P`.
  #
  # Returns a `BigInt` value as result.
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

    m_low % prime
  end

  # The elliptic curve jive addition of point `p(x, y)` and `q(x, y)`.
  #
  # We basically _draw_ a line between `p` and `q` which will intersect the
  # curve in the point `r` which will be mirrored over the `x`-axis.
  #
  # Paramters:
  # * `p` (`ECPoint`): the point `p(x, y)` to be used in the jive addition.
  # * `q` (`ECPoint`): the point `q(x, y)` to be used in the jive addition.
  # * `prime` (`BigInt`): the prime number that shapes the field, default: `EC_PRIME_P`.
  #
  # Returns another `ECPoint` as result.
  def self.ec_add(p : ECPoint, q : ECPoint, prime = EC_PRIME_P)
    x_delta = q.x - p.x
    x_inv = ec_mod_inv x_delta
    y_delta = q.y - p.y
    m = (y_delta * x_inv) % prime
    x = (m * m - p.x - q.x) % prime
    y = (m * (p.x - x) - p.y) % prime
    x = BigInt.new x
    y = BigInt.new y
    ECPoint.new x, y
  end

  # The elliptic curve juke point doubling of `p(x, y)`.
  #
  # This is a special case of addition where both points are the same.
  # We _draw_ a tangent line at `p` which will intersect the curve
  # at point `r` which will be mirrored over the `x`-axis.
  #
  # Paramters:
  # * `p` (`ECPoint`): the point `p(x, y)` to be used in the juke doubling.
  # * `prime` (`BigInt`): the prime number that shapes the field, default: `EC_PRIME_P`.
  #
  # Returns another `ECPoint` as result.
  def self.ec_double(p : ECPoint, prime = EC_PRIME_P)
    lam_numer = 3 * p.x * p.x + EC_FACTOR_A
    lam_denom = 2 * p.y
    lam_inv = ec_mod_inv lam_denom
    lam = (lam_numer * lam_inv) % prime
    x = (lam * lam - 2 * p.x) % prime
    y = (lam * (p.x - x) - p.y) % prime
    x = BigInt.new x
    y = BigInt.new y
    ECPoint.new x, y
  end

  # The elliptic curve sequence multiplication of point `p(x, y)` and
  # a skalar `s`.
  #
  # With `s` being a private key within the elliptic curve field size of `EC_ORDER_N`.
  #
  # Paramters:
  # * `p` (`ECPoint`): the point `p(x, y)` to be used in the sequencing.
  # * `s` (`BigInt`): a skalar, in most cases a private key.
  #
  # Returns another `ECPoint` as result, in most cases a public key.
  def self.ec_mul(p : ECPoint, s : BigInt)
    # catch skalars outside of the ec field size and exit
    if s === 0 || s >= EC_ORDER_N
      raise "invalid private key: outside of ec field size."
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
    q
  end
end
