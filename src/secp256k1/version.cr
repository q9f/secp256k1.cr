# Copyright 2019-2023 Afri Schoedon @q9f
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

# Provides the `Secp256k1` module with the elliptic curve  parameters
# used by the `Bitcoin`, `Ethereum`, and `Polkadot` blockchains. It's
# primarily used to generate key-pairs as well as signing messages and
# recoverying signatures.
#
# Ref: [secg.org/sec2-v2.pdf](https://www.secg.org/sec2-v2.pdf)
module Secp256k1
  # The `VERSION` of the `Secp256k1` module.
  VERSION = "0.5.1"
end
