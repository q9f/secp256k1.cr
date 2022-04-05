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

require "big/big_int"
require "openssl/digest"
require "openssl/hmac"
require "sha3"

require "./secp256k1/context"
require "./secp256k1/curve"
require "./secp256k1/key"
require "./secp256k1/num"
require "./secp256k1/point"
require "./secp256k1/signature"
require "./secp256k1/util"
require "./secp256k1/version"

module Secp256k1
  P = Num.new "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
  N = Num.new "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
  G = Point.new Num.new("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"), Num.new("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
end
