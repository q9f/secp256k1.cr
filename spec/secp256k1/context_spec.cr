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

require "../spec_helper"

describe Secp256k1::Context do
  it "can sign a message" do
    ctx = Context.new
    priv = Num.new "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
    key = Key.new priv
    msg = "Hello, World!"
    msg_hash = Util.sha256 msg
    10.times do
      sig = ctx.sign key, msg_hash
      valid = ctx.verify sig, msg_hash, key.public_key
      valid.should be_true
    end
  end

  it "can verify a public signature" do
    priv = Num.new "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
    key = Key.new priv
    r = Num.new "efc4f8d8bfc778463e4d4916d88bf3f057e6dc96cb2adc26dfb91959c4bef4a5"
    s = Num.new "cecd9a83fefafcb3cf99fde0c340bbe2fed9cdd0d25b53f4e08254acefb69ae0"
    v = Num.new "0"
    sig = Signature.new r, s, v
    hash = Num.new "be347331b4d87273e674b30384985c639069f852246e8c128417dbb1ca8ba812"
    valid = Context.new.verify sig, hash, key.public_key
    valid.should be_true
  end

  it "can handle r,s,v properly" do
    ctx = Context.new
    priv = Num.new "8e091dfb95a1b03cdd22890248c3f1b0f048186f2f3aa93257bc5271339eb306"
    key = Key.new priv
    msg = "Lorem, Ipsum!"
    hash = Util.keccak msg
    sig = ctx.sign key, hash
    expected_r = "87d391aca9b28b18f22f1fd997da380390270a8a1b0f4dcf63c272f56fa979ce"
    expected_s = "292330bd311a838a1b7a105624e81d127d53d4ece580832f65c59688aec6203a"
    expected_v = "00"
    sig.r.hex.should eq expected_r
    sig.s.hex.should eq expected_s
    sig.v.hex.should eq expected_v
    sig.compact.should eq "87d391aca9b28b18f22f1fd997da380390270a8a1b0f4dcf63c272f56fa979ce292330bd311a838a1b7a105624e81d127d53d4ece580832f65c59688aec6203a00"
    valid = ctx.verify sig, hash, key.public_key
    valid.should eq true
  end

  it "can determine k" do
    priv = Num.new "3b74fcc0b0c419a00d2d9e88b15fbd99e03920138da22e2a00c327b88d24cf45"
    hash = Util.sha256 "Henlo, Wordl"
    secret = BigInt.new "83193606619515454920331057246310791124858301167609726617990890481932799590618"
    k = Context.new.deterministic_k(priv, hash).dec
    k.should eq secret
  end
end
