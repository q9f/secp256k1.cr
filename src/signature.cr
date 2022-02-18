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

# Implements `ECDSASignature` generation and verification for `Secp256k1`
# elliptic curves.
# Ref: [cryptobook.nakov.com/digital-signatures/ecdsa-sign-verify-messages](https://cryptobook.nakov.com/digital-signatures/ecdsa-sign-verify-messages)
module Secp256k1::Signature
  # Signs a message hash and creates a signature proof using a private key.
  #
  # The ECDSA signing algorithm (RFC-6979) takes as input a message `msg`
  # and a private key `priv`. It produces as output a signature, which
  # consists of pair of integers `(r, s)`, where `r` is the `x`-coordinate
  # of a random point on our curve and `s` is the signature proof.
  #
  # Parameters:
  # * `hash` (`BigInt`): A message hash to sign.
  # * `priv` (`BigInt`): A private key to sign with.
  def self.sign(hash : BigInt, priv : BigInt)
    # Generate a deterministic number `k` from key and hash in the range `[1..n-1]`;
    k = deterministic_k(hash, priv)

    # Calculate the random point `r = k * g` and take its `x`-coordinate: `r = r.x`.
    point = Core.ec_mul(EC_BASE_G, k)
    r = point.x % EC_ORDER_N

    # Calculate the signature proof `s = k^-1 * (h + r * priv) % n`.
    k_inv = Core.ec_mod_inv k, EC_ORDER_N
    s = ((hash + r * priv) * k_inv) % EC_ORDER_N

    # Magnitude: The X value of the point R being more than the curve order.
    x_mag = point.x > EC_ORDER_N

    # Parity: The Y value of the point R being even.
    y_parity = (point.y % 2) == 0

    # Recovery ID
    # ref https://github.com/fivepiece/sign-verify-message/blob/master/signverifymessage.md#encoding-of-a-recoverable-signature
    rec_id : Int8 = -1
    if y_parity && !x_mag
      rec_id = 0
    elsif !y_parity && !x_mag
      rec_id = 1
    elsif y_parity && x_mag
      rec_id = 2
    elsif !y_parity && x_mag
      rec_id = 3
    end

    # Return the signature.
    ECDSASignature.new r, s, rec_id
  end

  # Verifies a signature of a message hash against a public key.
  #
  # The algorithm to verify an ECDSA signature takes as input the signed message `hash`
  # and the signature `(r, s, v)` produced from `sign` and the public key `pub`,
  # corresponding to the signer's private key. The result is boolean.
  #
  # Parameters:
  # * `hash` (`BigInt`): A SHA-256 hash of the message to verify.
  # * `sig` (`ECDSASignature`): A signature to verify the message.
  # * `pub` (`ECPoint`): A public key to verify the signature against.
  #
  # Returns _true_ if signature is valid.
  def self.verify(hash : BigInt, sig : ECDSASignature, pub : ECPoint)
    # Calculate the modular inverse of the signature proof: `s1 = s^{-1} % n`.
    s_inv = Core.ec_mod_inv sig.s, EC_ORDER_N

    # Recover the random point used during the signing: `R' = (h * s1) * g + (r * s1) * pub`
    p0 = Core.ec_mul EC_BASE_G, (hash * s_inv) % EC_ORDER_N
    p1 = Core.ec_mul pub, (sig.r * s_inv) % EC_ORDER_N
    p = Core.ec_add p0, p1

    # Calculate the signature validation result by comparing whether `r' == r`.
    sig.r === p.x
  end

  # Generates a deterministic random number from the message hash and the
  # private key. This guarantees deterministic signatures using this library.
  # It does not implement RFC-6979, though.
  #
  # Parameters:
  # * `hash` (`BigInt`): A message hash.
  # * `priv` (`BigInt`): A private key.
  private def self.deterministic_k(hash : BigInt, priv : BigInt)
    # @TODO implement RFC-6979 for deterministic k
    # Ref: https://bitcoin.stackexchange.com/questions/83784/tiny-secp256k1-and-ecdsa-signing-determinism
    merge = (hash + priv) % EC_ORDER_N
    BigInt.new Hash.sha256(merge.to_s(16).hexbytes), 16
  end
end
