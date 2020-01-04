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
module Secp256k1
  # an ecdsa signature
  class EC_Signature
    # the signature of a message
    property s : BigInt

    # the x coordinate of a random point
    property r : BigInt

    def initialize(@s : BigInt, @r : BigInt)
    end
  end

  # the ecdsa signing algorithm (rfc 6979) takes as input a message `msg`
  # and a private key `priv`. It produces as output a signature, which
  # consists of pair of integers {r, s}.
  def self.sign(msg : String, priv : BigInt)
    # calculate the message hash, using the cryptographic hash function sha-256
    hash = BigInt.new Crypto.sha256_string(msg), 16

    # generate securely a random number k in the range [1..n-1]
    # here: a new private key is the exact implementation of this requirement
    k = new_private_key

    # calculate the random point r = k * g and take its x-coordinate: r = r.x
    r = ec_mul(EC_BASE_G, k).x % EC_PARAM_PRIME

    # calculate the signature proof s = k^-1 * (h + r * priv) % n
    k_inv = ec_mod_inv k
    s = ((hash + r * priv) * k_inv) % EC_PARAM_PRIME
    sig = EC_Signature.new s, k
    return sig
  end

  def self.verify(msg : String, sig : EC_Signature, pub : EC_Point)
  end
end
