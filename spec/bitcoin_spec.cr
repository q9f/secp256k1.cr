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

describe Bitcoin do
  it "can generate valid bitcoin addresses" do
    prv = Num.new "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725"
    key = Key.new prv
    btc = Bitcoin::Account.new key
    btc.version.hex.should eq "00"
    btc.address.should eq "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"
    btc.address_compressed.should eq "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
    btc.wif.should eq "5J1F7GHadZG3sCCKHCwg8Jvys9xUbFsjLnGec4H125Ny1V9nR6V"
    btc.wif_compressed.should eq "Kx45GeUBSMPReYQwgXiKhG9FzNXrnCeutJp4yjTd5kKxCitadm3C"
  end

  it "can generate valid dogecoin addresses" do
    prv = Num.new "8c2b790d6645847fb70cdd7c14404f4c0a59966527c21aa286fc6f6d802e7d18"
    key = Key.new prv
    btc = Bitcoin::Account.new key, Num.new "1e"
    btc.version.hex.should eq "1e"
    btc.address.should eq "DDh3RAMeWnTWfH6q11uWkF74vMbMxqxa8X"
    btc.address_compressed.should eq "DP9Q6DP1GVjUAtcJcaCeR1psedXoC12Jtu"
    btc.wif.should eq "6KCMKj71s2X7vT8N8XHgh3CZsbwS5uVUxTEuAFZCNapyZbCbm6L"
    btc.wif_compressed.should eq "QTK6heqYoohwYvKWGCgeBii46MDFiegiPkpMDqF7CGJkeVEDqVWg"
  end
end
