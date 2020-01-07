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

# Implements `ECDSA_Signature` generation and verification for `Secp256k1`
# elliptic curves.
# Ref: [cryptobook.nakov.com/digital-signatures/ecdsa-sign-verify-messages](https://cryptobook.nakov.com/digital-signatures/ecdsa-sign-verify-messages)
module Secp256k1::Signature
  # Signs a message and creates a signature proof using a private key.
  #
  # The ECDSA signing algorithm (RFC-6979) takes as input a message `msg`
  # and a private key `priv`. It produces as output a signature, which
  # consists of pair of integers `(r, s)`, where `r` is the `x`-coordinate
  # of a random point on our curve and `s` is the signature proof.
  #
  # Parameters:
  # * `msg` (`String`): A message string to sign.
  # * `priv` (`BigInt`): A private key to sign with.
  #
  # ```
  # sig = Secp256k1::Signature.sign "Hello, World!", BigInt.new("b795cd2c5ce0cc632ca1f65e921b9c751b363e97fcaeec81c02a85b763448268", 16)
  # sig.r
  # # => "63945398370917837063250848409972066837033757647691696776146735867163610886143"
  # sig.s
  # # => "20291418537568297129028959685291490143232574306335372594306006819765182564103"
  # ```
  def self.sign(msg : String, priv : BigInt)
    # Calculate the message hash, using the cryptographic hash function SHA-256.
    hash = BigInt.new Hash.sha256_string(msg), 16

    # Securely generate a random number `k` in the range `[1..n-1]`;
    # here: a new private key is the exact implementation of this requirement.
    k = Util.new_private_key

    # Calculate the random point `r = k * g` and take its `x`-coordinate: `r = r.x`.
    r = Core.ec_mul(EC_BASE_G, k).x % EC_ORDER_N

    # Calculate the signature proof `s = k^-1 * (h + r * priv) % n`.
    k_inv = Core.ec_mod_inv k, EC_ORDER_N
    s = ((hash + r * priv) * k_inv) % EC_ORDER_N

    # Return the signature.
    sig = ECDSA_Signature.new r, s
    return sig
  end

  # Verifies a signature of a message against a public key.
  #
  # The algorithm to verify an ECDSA signature takes as input the signed message `msg`
  # and the signature `(r, s)` produced from `sign` and the public key `pub`,
  # corresponding to the signer's private key. The result is boolean.
  #
  # Parameters:
  # * `msg` (`String`): A message string to verify.
  # * `sig` (`ECDSA_Signature`): A signature to verify the message.
  # * `pub` (`EC_Point`): A public key to verify the signature against.
  #
  # ```
  # pub = Secp256k1::Util.restore_public_key "03d885aed4bcaf3a8c95a57e3be08caa1bd6a060a68b9795c03129073597fcb19a"
  # msg = "Hello, World!"
  # sig = Secp256k1::ECDSA_Signature.new BigInt.new("63945398370917837063250848409972066837033757647691696776146735867163610886143"), BigInt.new("20291418537568297129028959685291490143232574306335372594306006819765182564103")
  #
  # Secp256k1::Signature.verify msg, sig, pub
  # # => true
  # ```
  def self.verify(msg : String, sig : ECDSA_Signature, pub : EC_Point)
    # Calculate the message hash, with the same hash function used during the signing.
    hash = BigInt.new Hash.sha256_string(msg), 16
    return verify_hash hash, sig, pub
  end

  # Verifies a signature of a message hash against a public key.
  #
  # Same as `verify`, just using the hashed message directly.
  #
  # Parameters:
  # * `hash` (`BigInt`): A SHA-256 hash of the message to verify.
  # * `sig` (`ECDSA_Signature`): A signature to verify the message.
  # * `pub` (`EC_Point`): A public key to verify the signature against.
  #
  # Returns _true_ if signature is valid. See `verify` for usage example.
  def self.verify_hash(hash : BigInt, sig : ECDSA_Signature, pub : EC_Point)
    # Calculate the modular inverse of the signature proof: `s1 = s^{-1} % n`.
    s_inv = Core.ec_mod_inv sig.s, EC_ORDER_N

    # Recover the random point used during the signing: `R' = (h * s1) * g + (r * s1) * pub`
    p0 = Core.ec_mul EC_BASE_G, (hash * s_inv) % EC_ORDER_N
    p1 = Core.ec_mul pub, (sig.r * s_inv) % EC_ORDER_N
    p = Core.ec_add p0, p1

    # Calculate the signature validation result by comparing whether `r' == r`.
    return sig.r === p.x
  end
end
