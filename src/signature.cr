# Copyright 2019 @q9f
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

# implements ecdsa signature generation and verification for secp256k1
# ref: https://cryptobook.nakov.com/digital-signatures/ecdsa-sign-verify-messages
module Secp256k1::Signature
  # the ecdsa signing algorithm (rfc 6979) takes as input a message `msg`
  # and a private key `priv`. It produces as output a signature, which
  # consists of pair of integers `(r, s)`.
  def self.sign(msg : String, priv : BigInt)
    # calculate the message hash, using the cryptographic hash function sha-256
    hash = BigInt.new Hash.sha256_string(msg), 16

    # generate securely a random number k in the range [1..n-1]
    # here: a new private key is the exact implementation of this requirement
    k = Utils.new_private_key

    # calculate the random point r = k * g and take its x-coordinate: r = r.x
    r = Core.ec_mul(EC_BASE_G, k).x % EC_ORDER_N

    # calculate the signature proof s = k^-1 * (h + r * priv) % n
    k_inv = Core.ec_mod_inv k, EC_ORDER_N
    s = ((hash + r * priv) * k_inv) % EC_ORDER_N
    sig = ECDSA_Signature.new r, s
    return sig
  end

  # the algorithm to verify an ecdsa signature takes as input the signed message `msg`
  # and the signature `(r, s)` produced from self.sign and the public key `pub`,
  # corresponding to the signer's private key. The result is boolean.
  def self.verify(msg : String, sig : ECDSA_Signature, pub : EC_Point)
    # calculate the message hash, with the same hash function used during the signing
    hash = BigInt.new Hash.sha256_string(msg), 16
    return verify_hash hash, sig, pub
  end

  # same as self.verify, just using the hashed message directly
  def self.verify_hash(hash : BigInt, sig : ECDSA_Signature, pub : EC_Point)
    # calculate the modular inverse of the signature proof: s1 = s^{-1} % n
    s_inv = Core.ec_mod_inv sig.s, EC_ORDER_N

    # recover the random point used during the signing: R' = (h * s1) * g + (r * s1) * pub
    p0 = Core.ec_mul EC_BASE_G, (hash * s_inv) % EC_ORDER_N
    p1 = Core.ec_mul pub, (sig.r * s_inv) % EC_ORDER_N
    p = Core.ec_add p0, p1

    # calculate the signature validation result by comparing whether r' == r
    return sig.r === p.x
  end
end
