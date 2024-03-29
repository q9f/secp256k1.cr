var data = {lines:[
{"lineNum":"    1","line":"# Copyright 2019-2022 Afr Schoe @q9f"},
{"lineNum":"    2","line":"#"},
{"lineNum":"    3","line":"# Licensed under the Apache License, Version 2.0 (the \"License\");"},
{"lineNum":"    4","line":"# you may not use this file except in compliance with the License."},
{"lineNum":"    5","line":"# You may obtain a copy of the License at"},
{"lineNum":"    6","line":"#"},
{"lineNum":"    7","line":"#     http://www.apache.org/licenses/LICENSE-2.0"},
{"lineNum":"    8","line":"#"},
{"lineNum":"    9","line":"# Unless required by applicable law or agreed to in writing, software"},
{"lineNum":"   10","line":"# distributed under the License is distributed on an \"AS IS\" BASIS,"},
{"lineNum":"   11","line":"# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied."},
{"lineNum":"   12","line":"# See the License for the specific language governing permissions and"},
{"lineNum":"   13","line":"# limitations under the License."},
{"lineNum":"   14","line":""},
{"lineNum":"   15","line":"require \"big/big_int\""},
{"lineNum":"   16","line":"require \"openssl/digest\""},
{"lineNum":"   17","line":"require \"openssl/hmac\""},
{"lineNum":"   18","line":"require \"sha3\""},
{"lineNum":"   19","line":""},
{"lineNum":"   20","line":"require \"./secp256k1/context\""},
{"lineNum":"   21","line":"require \"./secp256k1/curve\""},
{"lineNum":"   22","line":"require \"./secp256k1/key\""},
{"lineNum":"   23","line":"require \"./secp256k1/num\""},
{"lineNum":"   24","line":"require \"./secp256k1/point\""},
{"lineNum":"   25","line":"require \"./secp256k1/signature\""},
{"lineNum":"   26","line":"require \"./secp256k1/util\""},
{"lineNum":"   27","line":"require \"./secp256k1/version\""},
{"lineNum":"   28","line":""},
{"lineNum":"   29","line":"# Provides the `Secp256k1` module with the elliptic curve  parameters"},
{"lineNum":"   30","line":"# used by the `Bitcoin`, `Ethereum`, and `Polkadot` blockchains. It\'s"},
{"lineNum":"   31","line":"# primarily used to generate key-pairs as well as signing messages and"},
{"lineNum":"   32","line":"# recoverying signatures."},
{"lineNum":"   33","line":"#"},
{"lineNum":"   34","line":"# Ref: [secg.org/sec2-v2.pdf](https://www.secg.org/sec2-v2.pdf)"},
{"lineNum":"   35","line":"module Secp256k1"},
{"lineNum":"   36","line":"  # The elliptic curve domain parameters over `F_p` associated with a"},
{"lineNum":"   37","line":"  # Koblitz curve `Secp256k1` are specified by the sextuple"},
{"lineNum":"   38","line":"  # `T = (p, a, b, G, n, h)` where the finite field `F_p` is defined by"},
{"lineNum":"   39","line":"  # the prime `p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1`."},
{"lineNum":"   40","line":"  P = Num.new \"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f\"","class":"lineCov","hits":"3","order":"1","possible_hits":"3",},
{"lineNum":"   41","line":""},
{"lineNum":"   42","line":"  # The order `n` of `G` defines the finite size of the Secp256k1 field `E`."},
{"lineNum":"   43","line":"  N = Num.new \"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141\"","class":"lineCov","hits":"3","order":"15","possible_hits":"3",},
{"lineNum":"   44","line":""},
{"lineNum":"   45","line":"  # A commonly used base point `G` with coordinates `x` and `y`"},
{"lineNum":"   46","line":"  # satisfying `y^2 = x^3 + 7`."},
{"lineNum":"   47","line":"  G = Point.new(","class":"lineCov","hits":"3","order":"16","possible_hits":"3",},
{"lineNum":"   48","line":"    Num.new(\"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\"),","class":"lineCov","hits":"1","order":"17","possible_hits":"1",},
{"lineNum":"   49","line":"    Num.new(\"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8\")","class":"lineCov","hits":"1","order":"18","possible_hits":"1",},
{"lineNum":"   50","line":"  )"},
{"lineNum":"   51","line":"end"},
]};
var percent_low = 25;var percent_high = 75;
var header = { "command" : "run_coverage", "date" : "2022-04-06 16:56:27", "instrumented" : 5, "covered" : 5,};
var merged_data = [];
