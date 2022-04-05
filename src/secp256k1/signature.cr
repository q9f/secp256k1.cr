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

class Secp256k1::Signature
  property r : Num
  property s : Num
  property v : Num

  def initialize(r : Num, s : Num, v : Num)
    @r = r
    @s = s
    @v = v
  end

  def compact
    "#{r.to_zpadded_hex}#{s.to_zpadded_hex}#{v.to_hex}"
  end
end
