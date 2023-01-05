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

require "../spec_helper"

describe Secp256k1::Signature do
  it "can create compact signatures" do
    r = Num.new "558f97c6f9ac0636cf977ae4fc4982688286e78db45f0f92f154908982475264"
    s = Num.new "95d194e57a40ffd8a69dd94a21ddb9133e3b584ef351fe750250ff964b16bbf0"
    v = Num.new "1"
    sig = Signature.new r, s, v
    sig.compact.should eq "558f97c6f9ac0636cf977ae4fc4982688286e78db45f0f92f15490898247526495d194e57a40ffd8a69dd94a21ddb9133e3b584ef351fe750250ff964b16bbf001"
  end
end
