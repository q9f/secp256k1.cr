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

describe Secp256k1::Curve do
  it "computes modular multiplicative inverse of a" do
    a = Num.new "5d5c75e7a6cd4b7fd7fbbf3fe78d97695b59c02a6c1c6a25d052fc736d9f07e6"
    i = Curve.mod_inv a
    i.hex.should eq "3132ba18c7818bbafca8ed17c7f5b2ced03a2b5894d5a39fbbfc62f834042408"
  end

  it "computes ec addition of p and q" do
    r = Curve.add G, G
    r.x.hex.should eq "0c8333020c4688a754bf3ad462f1e9f1fac80649a463ae4d4c1afd48d20fccff"
    r.y.hex.should eq "b7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777"
    q = Point.new G.y, G.x
    s = Curve.add G, q
    s.x.hex.should eq "3e06bf09df7f7fee4cbaa16e2367ec50004c4edc2bac830d09c5ae13edf70fe0"
    s.y.hex.should eq "7c0d7e13befeffdc997542dc46cfd8a000989db85759061a138b5c27dbee1fbf"
  end

  it "computes ec doubling of p" do
    p = Curve.double G
    p.x.hex.should eq "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    p.y.hex.should eq "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"
  end
end
