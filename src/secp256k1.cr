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

require "./bip39.cr"
require "./bitcoin.cr"
require "./constants.cr"
require "./core.cr"
require "./ethereum.cr"
require "./hash.cr"
require "./signature.cr"
require "./structs.cr"
require "./util.cr"
require "./version.cr"

# Implements 256-bit `Secp256k1` Koblitz elliptic curve.
# Ref: [secg.org/sec2-v2.pdf](https://www.secg.org/sec2-v2.pdf)
#
# `Secp256k1` has the characteristic prime `p`, it is defined over the prime field ℤ_p.
# Ref: [en.bitcoin.it/wiki/Secp256k1](https://en.bitcoin.it/wiki/Secp256k1)
module Secp256k1
  # Exposes the `Secp256k1` module.
end
