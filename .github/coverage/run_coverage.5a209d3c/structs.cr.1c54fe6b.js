var data = {lines:[
{"lineNum":"    1","line":"# Copyright 2019-2020 @q9f"},
{"lineNum":"    2","line":"#"},
{"lineNum":"    3","line":"# Licensed under the Apache License, Version 2.0 (the \"License\");"},
{"lineNum":"    4","line":"# you may not use this file except in compliance with the License."},
{"lineNum":"    5","line":"# You may obtain a copy of the License at"},
{"lineNum":"    6","line":"#"},
{"lineNum":"    7","line":"#     http://www.apache.org/licenses/LICENSE-2.0"},
{"lineNum":"    8","line":"#"},
{"lineNum":"    9","line":"# Unless required by applicable law or agreed to in writing, software"},
{"lineNum":"   10","line":"# distributed under the License is distributed on an \"AS IS\" BASIS,"},
{"lineNum":"   11","line":"# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied."},
{"lineNum":"   12","line":"# See the License for the specific language governing permissions and"},
{"lineNum":"   13","line":"# limitations under the License."},
{"lineNum":"   14","line":""},
{"lineNum":"   15","line":"# Implements 256-bit `Secp256k1` Koblitz elliptic curve."},
{"lineNum":"   16","line":"# Ref: [secg.org/sec2-v2.pdf](https://www.secg.org/sec2-v2.pdf)"},
{"lineNum":"   17","line":"#"},
{"lineNum":"   18","line":"# `Secp256k1` has the characteristic prime `p`, it is defined over the prime field ℤ_p."},
{"lineNum":"   19","line":"# Ref: [en.bitcoin.it/wiki/Secp256k1](https://en.bitcoin.it/wiki/Secp256k1)"},
{"lineNum":"   20","line":"module Secp256k1"},
{"lineNum":"   21","line":"  # Implements a `Secp256k1` key pair containing a private and a public key."},
{"lineNum":"   22","line":"  #"},
{"lineNum":"   23","line":"  # Properties:"},
{"lineNum":"   24","line":"  # * `private_key` (`BigInt`): the secret as known as the private key."},
{"lineNum":"   25","line":"  # * `public_key` (`ECPoint`): the point on the elliptic curve as known as the public key."},
{"lineNum":"   26","line":"  #"},
{"lineNum":"   27","line":"  # ```"},
{"lineNum":"   28","line":"  # key = Secp256k1::Keypair.new"},
{"lineNum":"   29","line":"  # key.get_secret"},
{"lineNum":"   30","line":"  # # => \"53d77137b39427a35d8c4b187f532d3912e1e7135985e730633e1e3c1b87ce97\""},
{"lineNum":"   31","line":"  # key.to_s"},
{"lineNum":"   32","line":"  # # => \"e097fc69f0b92f711620511c07fefdd648e469df46b1e4385a00a1786f6bc55b7d9011bb589e883d8a7947cfb37dc6b3c8beae9c614cab4a83009bd9d8732a9f\""},
{"lineNum":"   33","line":"  # ```"},
{"lineNum":"   34","line":"  class Keypair"},
{"lineNum":"   35","line":"    # The secret as known as the private key."},
{"lineNum":"   36","line":"    property private_key : BigInt"},
{"lineNum":"   37","line":""},
{"lineNum":"   38","line":"    # The point on the elliptic curve as known as the public key."},
{"lineNum":"   39","line":"    property public_key : ECPoint"},
{"lineNum":"   40","line":""},
{"lineNum":"   41","line":"    # Generates a new keypair using a fresh random private key."},
{"lineNum":"   42","line":"    #"},
{"lineNum":"   43","line":"    # ```"},
{"lineNum":"   44","line":"    # key = Secp256k1::Keypair.new"},
{"lineNum":"   45","line":"    # # => #<Secp256k1::Keypair:0x7f8be5611d80>"},
{"lineNum":"   46","line":"    # ```"},
{"lineNum":"   47","line":"    def initialize"},
{"lineNum":"   48","line":"      @private_key = Util.new_private_key"},
{"lineNum":"   49","line":"      @public_key = Util.public_key_from_private @private_key"},
{"lineNum":"   50","line":"    end"},
{"lineNum":"   51","line":""},
{"lineNum":"   52","line":"    # Generates a new keypair using a provided private key."},
{"lineNum":"   53","line":"    #"},
{"lineNum":"   54","line":"    # Parameters:"},
{"lineNum":"   55","line":"    # * `private_key` (`BigInt`): the secret as known as the private key."},
{"lineNum":"   56","line":"    #"},
{"lineNum":"   57","line":"    # ```"},
{"lineNum":"   58","line":"    # key = Secp256k1::Keypair.new BigInt.new(\"53d77137b39427a35d8c4b187f532d3912e1e7135985e730633e1e3c1b87ce97\", 16)"},
{"lineNum":"   59","line":"    # # => #<Secp256k1::Keypair:0x7f8be5611d80>"},
{"lineNum":"   60","line":"    # ```"},
{"lineNum":"   61","line":"    def initialize(@private_key)","class":"lineCov","hits":"4","order":"26","possible_hits":"4",},
{"lineNum":"   62","line":"      @public_key = Util.public_key_from_private @private_key","class":"lineCov","hits":"1","order":"27","possible_hits":"1",},
{"lineNum":"   63","line":"    end"},
{"lineNum":"   64","line":""},
{"lineNum":"   65","line":"    # Gets the private key as hexadecimal formatted string literal."},
{"lineNum":"   66","line":"    #"},
{"lineNum":"   67","line":"    # ```"},
{"lineNum":"   68","line":"    # key.get_secret"},
{"lineNum":"   69","line":"    # # => \"53d77137b39427a35d8c4b187f532d3912e1e7135985e730633e1e3c1b87ce97\""},
{"lineNum":"   70","line":"    # ```"},
{"lineNum":"   71","line":"    def get_secret"},
{"lineNum":"   72","line":"      Util.to_padded_hex_32 @private_key"},
{"lineNum":"   73","line":"    end"},
{"lineNum":"   74","line":""},
{"lineNum":"   75","line":"    # Gets the key formatted as uncompressed public key string."},
{"lineNum":"   76","line":"    #"},
{"lineNum":"   77","line":"    # ```"},
{"lineNum":"   78","line":"    # key.to_s"},
{"lineNum":"   79","line":"    # # => \"e097fc69f0b92f711620511c07fefdd648e469df46b1e4385a00a1786f6bc55b7d9011bb589e883d8a7947cfb37dc6b3c8beae9c614cab4a83009bd9d8732a9f\""},
{"lineNum":"   80","line":"    # ```"},
{"lineNum":"   81","line":"    def to_s","class":"lineCov","hits":"2","order":"269","possible_hits":"2",},
{"lineNum":"   82","line":"      Util.public_key_uncompressed @public_key","class":"lineCov","hits":"2","order":"30","possible_hits":"2",},
{"lineNum":"   83","line":"    end"},
{"lineNum":"   84","line":"  end"},
{"lineNum":"   85","line":""},
{"lineNum":"   86","line":"  # A point in the two-dimensional space of an elliptic curve."},
{"lineNum":"   87","line":"  #"},
{"lineNum":"   88","line":"  # Properties:"},
{"lineNum":"   89","line":"  # * `x` (`BigInt`): the position on the x-axis."},
{"lineNum":"   90","line":"  # * `y` (`BigInt`): the position on the y-axis."},
{"lineNum":"   91","line":"  #"},
{"lineNum":"   92","line":"  # ```"},
{"lineNum":"   93","line":"  # p = ECPoint.new BigInt.new(0), BigInt.new(0)"},
{"lineNum":"   94","line":"  # p.x"},
{"lineNum":"   95","line":"  # # => 0"},
{"lineNum":"   96","line":"  # p.y"},
{"lineNum":"   97","line":"  # # => 0"},
{"lineNum":"   98","line":"  # ```"},
{"lineNum":"   99","line":"  struct ECPoint"},
{"lineNum":"  100","line":"    # The position on the x-axis."},
{"lineNum":"  101","line":"    property x : BigInt"},
{"lineNum":"  102","line":""},
{"lineNum":"  103","line":"    # The position on the y-axis."},
{"lineNum":"  104","line":"    property y : BigInt"},
{"lineNum":"  105","line":""},
{"lineNum":"  106","line":"    # An ECPoint always requires two coordinates `x`, `y`."},
{"lineNum":"  107","line":"    #"},
{"lineNum":"  108","line":"    # Parameters:"},
{"lineNum":"  109","line":"    # * `x` (`BigInt`): the position on the x-axis."},
{"lineNum":"  110","line":"    # * `y` (`BigInt`): the position on the y-axis."},
{"lineNum":"  111","line":"    def initialize(@x : BigInt, @y : BigInt)","class":"lineCov","hits":"4","order":"7","possible_hits":"4",},
{"lineNum":"  112","line":"    end"},
{"lineNum":"  113","line":"  end"},
{"lineNum":"  114","line":""},
{"lineNum":"  115","line":"  # A basic ECDSA Signature containing a random point `r` and the"},
{"lineNum":"  116","line":"  # signature proof `s`."},
{"lineNum":"  117","line":"  #"},
{"lineNum":"  118","line":"  # See: `Signature` for signature generation."},
{"lineNum":"  119","line":"  #"},
{"lineNum":"  120","line":"  # Properties:"},
{"lineNum":"  121","line":"  # * `r` (`BigInt`): the `x` coordinate of a random point `R`."},
{"lineNum":"  122","line":"  # * `s` (`BigInt`): the signature proof of a message."},
{"lineNum":"  123","line":"  #"},
{"lineNum":"  124","line":"  # ```"},
{"lineNum":"  125","line":"  # sig = ECDSASignature.new r.x, proof"},
{"lineNum":"  126","line":"  # ```"},
{"lineNum":"  127","line":"  struct ECDSASignature"},
{"lineNum":"  128","line":"    # The `x` coordinate of a random point `R`."},
{"lineNum":"  129","line":"    property r : BigInt"},
{"lineNum":"  130","line":""},
{"lineNum":"  131","line":"    # The signature proof of a message."},
{"lineNum":"  132","line":"    property s : BigInt"},
{"lineNum":"  133","line":""},
{"lineNum":"  134","line":"    # A signature always requires the random point `r` and the signature proof `s`."},
{"lineNum":"  135","line":"    #"},
{"lineNum":"  136","line":"    # Parameters:"},
{"lineNum":"  137","line":"    # * `r` (`BigInt`): the `x` coordinate of a random point `R`."},
{"lineNum":"  138","line":"    # * `s` (`BigInt`): the signature proof of a message."},
{"lineNum":"  139","line":"    def initialize(@r : BigInt, @s : BigInt)","class":"lineCov","hits":"4","order":"293","possible_hits":"4",},
{"lineNum":"  140","line":"    end"},
{"lineNum":"  141","line":"  end"},
{"lineNum":"  142","line":"end"},
]};
var percent_low = 25;var percent_high = 75;
var header = { "command" : "run_coverage", "date" : "2021-12-13 12:03:11", "instrumented" : 6, "covered" : 6,};
var merged_data = [];
