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

class Secp256k1::Key
  property private_key : Num
  property public_key : Point

  def initialize
    @private_key = Num.new
    @public_key = Point.new @private_key
  end

  def initialize(priv : Num)
    @private_key = priv
    @public_key = Point.new @private_key
  end

  def private_hex
    @private_key.to_zpadded_hex
  end

  def private_bytes
    @private_key.to_zpadded_bytes
  end

  def public_hex
    @public_key.uncompressed
  end

  def public_bytes
    Num.new(@public_key.uncompressed).to_bytes
  end
end
