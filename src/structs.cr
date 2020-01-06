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

# custom data types for the secp256k1 module
module Secp256k1
  # A point in the two-dimensional space of an elliptic curve
  class EC_Point
    # the position on the x-axis
    property x : BigInt

    # the position on the y-axis
    property y : BigInt

    def initialize(@x : BigInt, @y : BigInt)
    end
  end

  # an ecdsa signature
  class ECDSA_Signature
    # the x coordinate of a random point
    property r : BigInt

    # the signature proof of a message
    property s : BigInt

    def initialize(@r : BigInt, @s : BigInt)
    end
  end
end
