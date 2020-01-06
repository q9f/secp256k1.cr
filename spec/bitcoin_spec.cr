# Copyright 2019 @q9f
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

# tests for the Secp256k1::Bitcoin module
describe Secp256k1::Bitcoin do
  # tests a known bitcoin address from a known private key
  it "can generate a valid bitcoin address" do
    # private key and address taken from the bitcoin wiki
    # ref: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    adr = Secp256k1::Bitcoin.address_from_private "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725"
    adr.should eq "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"

    # uncompressed dogecoin address with version byte "1e"
    # doge: http://coinok.pw/wallet/doge/
    dog = Secp256k1::Bitcoin.address_from_private "8c2b790d6645847fb70cdd7c14404f4c0a59966527c21aa286fc6f6d802e7d18", "1e", false
    dog.should eq "DDh3RAMeWnTWfH6q11uWkF74vMbMxqxa8X"

    # compressed dogecoin address
    dog = Secp256k1::Bitcoin.address_from_private "8c2b790d6645847fb70cdd7c14404f4c0a59966527c21aa286fc6f6d802e7d18", "1e"
    dog.should eq "DP9Q6DP1GVjUAtcJcaCeR1psedXoC12Jtu"
  end

  # generates a mini private key and checks its attributes
  # ref: https://en.bitcoin.it/wiki/Mini_private_key_format
  it "can generate a valid mini private key" do
    mini = Secp256k1::Bitcoin.new_mini_private_key

    # should start with capital "S"
    mini[0, 1].should eq "S"

    # should be 30 characters long
    mini.size.should eq 30

    # the hash of the mini key with question mark should start with "00"
    sha2 = Secp256k1::Hash.sha256_string "#{mini}?"
    sha2[0, 2].should eq "00"
  end

  # tests the mini key from the bitcoin wiki
  # ref: https://en.bitcoin.it/wiki/Mini_private_key_format
  it "can generate a valid private key from mini key" do
    mini = "S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy"
    priv = Secp256k1::Bitcoin.private_key_from_mini mini
    priv.should eq BigInt.new "4c7a9640c72dc2099f23715d0c8a0d8a35f8906e3cab61dd3f78b67bf887c9ab", 16
    sha2 = Secp256k1::Hash.sha256_string "#{mini}?"
    sha2.should eq "000f2453798ad4f951eecced2242eaef3e1cbc8a7c813c203ac7ffe57060355d"
  end

  # tests the wallet import format with the keys from the bitcoin wiki and stack exchange
  it "can provide the correct wallet import format" do
    # ref: https://en.bitcoin.it/wiki/Wallet_import_format
    priv = BigInt.new "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d", 16
    wif = Secp256k1::Bitcoin.wif_from_private priv
    wif.should eq "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
    wif_compr = Secp256k1::Bitcoin.wif_compressed_from_private priv
    wif_compr.should eq "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617"

    # ref: https://bitcoin.stackexchange.com/questions/68065/private-key-to-wif-compressed-which-one-is-correct
    priv = BigInt.new "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 16
    wif = Secp256k1::Bitcoin.wif_from_private priv
    wif.should eq "5HpHgWkLaovGWySEFpng1XQ6pdG1TzNWR7SrETvfTRVdKHNXZh8"
    wif_compr = Secp256k1::Bitcoin.wif_compressed_from_private priv
    wif_compr.should eq "KwDidQJHSE67VJ6MWRvbBKAxhD3F48DvqRT6JRqrjd7MHLBjGF7V"
  end

  # tests the wallet import format with the keys from the bitcoin wiki
  # ref: https://en.bitcoin.it/wiki/Wallet_import_format
  it "can extract private keys from wallet import format" do
    uncm = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
    comp = "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617"
    priv_uncm = Secp256k1::Bitcoin.private_key_from_wif uncm
    priv_comp = Secp256k1::Bitcoin.private_key_from_wif comp

    # both should map to the same private key
    priv_uncm.should eq "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d"
    priv_comp.should eq "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d"
    priv_comp.should eq priv_uncm

    # should not allow invalid wif
    expect_raises Exception, "invalid wallet import format (invalid wif size: 50)" do
      inv = Secp256k1::Bitcoin.private_key_from_wif "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
    end
  end

  # tests the wallet import format with the keys from the bitcoin wiki and stack exchange
  # ref: https://en.bitcoin.it/wiki/Wallet_import_format
  # ref: https://bitcoin.stackexchange.com/questions/68065/private-key-to-wif-compressed-which-one-is-correct
  it "can detect invalid wallet import formats" do
    uncm0 = Secp256k1::Bitcoin.wif_is_valid? "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
    comp0 = Secp256k1::Bitcoin.wif_is_valid? "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617"
    uncm1 = Secp256k1::Bitcoin.wif_is_valid? "5HpHgWkLaovGWySEFpng1XQ6pdG1TzNWR7SrETvfTRVdKHNXZh8"
    comp1 = Secp256k1::Bitcoin.wif_is_valid? "KwDidQJHSE67VJ6MWRvbBKAxhD3F48DvqRT6JRqrjd7MHLBjGF7V"

    # all keys should be valid
    uncm0.should eq true
    comp0.should eq true
    uncm1.should eq true
    comp1.should eq true

    # invalid wif should not pass
    inv0 = Secp256k1::Bitcoin.wif_is_valid? "2SaK8jfqHYLmZdtSdWu1XrXCxpU8u2nt4civAPveeX8P2X5ceivrpf"
    inv1 = Secp256k1::Bitcoin.wif_is_valid? "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
    inv0.should eq false
    inv1.should eq false
  end

  # tests address generation from wif with keys found on the interwebs
  # ref: https://allprivatekeys.com/what-is-wif
  # ref: http://coinok.pw/wallet/doge/ (doge)
  it "should generate valid address from wif" do
    # 8c2b790d6645847fb70cdd7c14404f4c0a59966527c21aa286fc6f6d802e7d18
    wif = "6KCMKj71s2X7vT8N8XHgh3CZsbwS5uVUxTEuAFZCNapyZbCbm6L"
    adr = Secp256k1::Bitcoin.address_from_wif wif
    adr.should eq "DDh3RAMeWnTWfH6q11uWkF74vMbMxqxa8X"

    # same but compressed
    wif = "QTK6heqYoohwYvKWGCgeBii46MDFiegiPkpMDqF7CGJkeVEDqVWg"
    adr = Secp256k1::Bitcoin.address_from_wif wif
    adr.should eq "DP9Q6DP1GVjUAtcJcaCeR1psedXoC12Jtu"

    # 0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d
    wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
    adr = Secp256k1::Bitcoin.address_from_wif wif
    adr.should eq "1GAehh7TsJAHuUAeKZcXf5CnwuGuGgyX2S"

    # same but compressed
    wif = "5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KF"
    adr = Secp256k1::Bitcoin.address_from_wif wif
    adr.should eq "1CC3X2gu58d6wXUWMffpuzN9JAfTUWu4Kj"
  end
end
