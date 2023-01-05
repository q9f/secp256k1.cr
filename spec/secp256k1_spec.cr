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

require "./spec_helper"

describe Secp256k1 do
  it "has some version string" do
    VERSION.should eq "0.5.1"
  end

  it "has correct constants" do
    P.to_hex.should eq "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
    N.to_hex.should eq "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
    G.uncompressed.should eq "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
    G.compressed.should eq "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
  end
end
