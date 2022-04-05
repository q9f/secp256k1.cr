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

module Secp256k1::Curve
  extend self

  def sign(hash : Num)
  end

  def mod_inv(a : Num | BigInt, prime = P)
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

  def add(p : Point, q : Point, prime = P)
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

  def double(p : Point, prime = P)
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

  def mul(p : Point, s : Num | BigInt)
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
