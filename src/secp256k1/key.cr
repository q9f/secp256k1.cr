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

# Provides a `Secp256k1` keypair containing a secret number (private key)
# and a public point on the elliptic curve (public key).
#
# Properties:
# * `private_key` (`Num`): the secret number representing the private key.
# * `public_key` (`Point`): the point on the elliptic curve representing the public key.
class Secp256k1::Key
  # The secret number representing the private key.
  getter private_key : Num
  # The point on the elliptic curve representing the public key.
  getter public_key : Point

  # Creates a new, random `Secp256k1` keypair.
  #
  # ```
  # Key.new
  # # => #<Secp256k1::Key:0x7fad7235aee0
  # #          @private_key=#<Secp256k1::Num:0x7fad7235d300
  # #              @hex="3ccf84820c20d5e8c536ba84c52ba410375b29b1812b5f7e722445c969a0fb30",
  # #              @dec=27505422793993207218034260454067205887515304192802142316084292370834437241648,
  # #              @bin=Bytes[60, 207, 132, 130, 12, 32, 213, 232, 197, 54, 186, 132, 197, 43, 164, 16, 55, 91, 41, 177, 129, 43, 95, 126, 114, 36, 69, 201, 105, 160, 251, 48]>,
  # #          @public_key=#<Secp256k1::Point:0x7fad7235ad20
  # #              @x=#<Secp256k1::Num:0x7fad69294ec0
  # #                  @hex="cd4a8712ee6efc15b5abe37c0dbfa979d89c427d3fe24b076008decefe94dba2",
  # #                  @dec=92855812888509048668847240903552964511053624688683992093822247249407942908834,
  # #                  @bin=Bytes[205, 74, 135, 18, 238, 110, 252, 21, 181, 171, 227, 124, 13, 191, 169, 121, 216, 156, 66, 125, 63, 226, 75, 7, 96, 8, 222, 206, 254, 148, 219, 162]>,
  # #              @y=#<Secp256k1::Num:0x7fad69294e80
  # #                  @hex="81363d298e4a40ebcb13f1afa85a0b94b967f243ee59a59010cb5deaf0d7b66c",
  # #                  @dec=58444189335609256006902338825877424261513225250255958585656342678587884156524,
  # #                  @bin=Bytes[129, 54, 61, 41, 142, 74, 64, 235, 203, 19, 241, 175, 168, 90, 11, 148, 185, 103, 242, 67, 238, 89, 165, 144, 16, 203, 93, 234, 240, 215, 182, 108]>>>
  # ```
  def initialize
    @private_key = Num.new
    @public_key = Point.new @private_key
  end

  # Creates a public-private keypair from an existing private key.
  #
  # Parameters:
  # * `priv` (`Num`): the private key for the keypair.
  #
  # ```
  # priv = Num.new "3ccf84820c20d5e8c536ba84c52ba410375b29b1812b5f7e722445c969a0fb30"
  # Key.new priv
  # # => #<Secp256k1::Key:0x7fc6b2f54ee0
  # #          @private_key=#<Secp256k1::Num:0x7fad7235d300
  # #              @hex="3ccf84820c20d5e8c536ba84c52ba410375b29b1812b5f7e722445c969a0fb30",
  # #              @dec=27505422793993207218034260454067205887515304192802142316084292370834437241648,
  # #              @bin=Bytes[60, 207, 132, 130, 12, 32, 213, 232, 197, 54, 186, 132, 197, 43, 164, 16, 55, 91, 41, 177, 129, 43, 95, 126, 114, 36, 69, 201, 105, 160, 251, 48]>,
  # #          @public_key=#<Secp256k1::Point:0x7fad7235ad20
  # #              @x=#<Secp256k1::Num:0x7fad69294ec0
  # #                  @hex="cd4a8712ee6efc15b5abe37c0dbfa979d89c427d3fe24b076008decefe94dba2",
  # #                  @dec=92855812888509048668847240903552964511053624688683992093822247249407942908834,
  # #                  @bin=Bytes[205, 74, 135, 18, 238, 110, 252, 21, 181, 171, 227, 124, 13, 191, 169, 121, 216, 156, 66, 125, 63, 226, 75, 7, 96, 8, 222, 206, 254, 148, 219, 162]>,
  # #              @y=#<Secp256k1::Num:0x7fad69294e80
  # #                  @hex="81363d298e4a40ebcb13f1afa85a0b94b967f243ee59a59010cb5deaf0d7b66c",
  # #                  @dec=58444189335609256006902338825877424261513225250255958585656342678587884156524,
  # #                  @bin=Bytes[129, 54, 61, 41, 142, 74, 64, 235, 203, 19, 241, 175, 168, 90, 11, 148, 185, 103, 242, 67, 238, 89, 165, 144, 16, 203, 93, 234, 240, 215, 182, 108]>>>
  # ```
  def initialize(priv : Num)
    @private_key = priv
    @public_key = Point.new @private_key
  end

  # Returns the private key as hexadecimal string literal.
  #
  # ```
  # Key.new(Num.new "3ccf84820c20d5e8c536ba84c52ba410375b29b1812b5f7e722445c969a0fb30").private_hex
  # # => "3ccf84820c20d5e8c536ba84c52ba410375b29b1812b5f7e722445c969a0fb30"
  # ```
  def private_hex : String
    @private_key.to_zpadded_hex
  end

  # Returns the private key as binary byte slice.
  #
  # ```
  # Key.new(Num.new "3ccf84820c20d5e8c536ba84c52ba410375b29b1812b5f7e722445c969a0fb30").private_bytes
  # # => Bytes[60, 207, 132, 130, 12, 32, 213, 232, 197, 54, 186, 132, 197, 43, 164, 16, 55, 91, 41, 177, 129, 43, 95, 126, 114, 36, 69, 201, 105, 160, 251, 48]
  # ```
  def private_bytes : Bytes
    @private_key.to_zpadded_bytes
  end

  # Returns the public key as uncompressed, hexadecimal string literal.
  #
  # ```
  # Key.new(Num.new "3ccf84820c20d5e8c536ba84c52ba410375b29b1812b5f7e722445c969a0fb30").public_hex
  # # => "04cd4a8712ee6efc15b5abe37c0dbfa979d89c427d3fe24b076008decefe94dba281363d298e4a40ebcb13f1afa85a0b94b967f243ee59a59010cb5deaf0d7b66c"
  # ```
  def public_hex : String
    @public_key.uncompressed
  end

  # Returns the public key as compressed, hexadecimal string literal.
  #
  # ```
  # Key.new(Num.new "3ccf84820c20d5e8c536ba84c52ba410375b29b1812b5f7e722445c969a0fb30").public_hex_compressed
  # # => "02cd4a8712ee6efc15b5abe37c0dbfa979d89c427d3fe24b076008decefe94dba2"
  # ```
  def public_hex_compressed : String
    @public_key.compressed
  end

  # Returns the public key as uncompressed, binary byte slice.
  #
  # ```
  # Key.new(Num.new "3ccf84820c20d5e8c536ba84c52ba410375b29b1812b5f7e722445c969a0fb30").public_bytes
  # # => Bytes[4, 205, 74, 135, 18, 238, 110, 252, 21, 181, 171, 227, 124, 13, 191, 169, 121, 216, 156, 66, 125, 63, 226, 75, 7, 96, 8, 222, 206, 254, 148, 219, 162, 129, 54, 61, 41, 142, 74, 64, 235, 203, 19, 241, 175, 168, 90, 11, 148, 185, 103, 242, 67, 238, 89, 165, 144, 16, 203, 93, 234, 240, 215, 182, 108]
  # ```
  def public_bytes : Bytes
    Num.new(@public_key.uncompressed).to_bytes
  end

  # Returns the public key as compressed, binary byte slice.
  #
  # ```
  # Key.new(Num.new "3ccf84820c20d5e8c536ba84c52ba410375b29b1812b5f7e722445c969a0fb30").public_bytes_compressed
  # # => Bytes[2, 205, 74, 135, 18, 238, 110, 252, 21, 181, 171, 227, 124, 13, 191, 169, 121, 216, 156, 66, 125, 63, 226, 75, 7, 96, 8, 222, 206, 254, 148, 219, 162]
  # ```
  def public_bytes_compressed : Bytes
    Num.new(@public_key.compressed).to_bytes
  end
end
