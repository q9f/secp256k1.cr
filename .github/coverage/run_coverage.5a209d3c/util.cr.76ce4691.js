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
{"lineNum":"   15","line":"# Links GMP to directly leverage integer exponentiation."},
{"lineNum":"   16","line":"@[Link(\"gmp\")]"},
{"lineNum":"   17","line":"lib LibGMP"},
{"lineNum":"   18","line":"  fun mpz_powm_sec = __gmpz_powm_sec(rop : MPZ*, base : MPZ*, exp : MPZ*, mod : MPZ*)"},
{"lineNum":"   19","line":"end"},
{"lineNum":"   20","line":""},
{"lineNum":"   21","line":"# A collection of utilities for `Secp256k1` key management, e.g., private key"},
{"lineNum":"   22","line":"# generation, public key conversions, key formatting, or hex padding."},
{"lineNum":"   23","line":"module Secp256k1::Util"},
{"lineNum":"   24","line":"  # A generic utility to encode single hex bytes as strings, e.g., \"07\""},
{"lineNum":"   25","line":"  #"},
{"lineNum":"   26","line":"  # Parameters:"},
{"lineNum":"   27","line":"  # * `i` (`Int32`): the integer to be formatted as padded hex byte."},
{"lineNum":"   28","line":"  #"},
{"lineNum":"   29","line":"  # ```"},
{"lineNum":"   30","line":"  # Secp256k1::Util.to_padded_hex_01 7"},
{"lineNum":"   31","line":"  # # => \"07\""},
{"lineNum":"   32","line":"  # ```"},
{"lineNum":"   33","line":"  def self.to_padded_hex_01(i : Int32)","class":"lineCov","hits":"1","order":"121","possible_hits":"1",},
{"lineNum":"   34","line":"    hex = i.to_s 16","class":"lineCov","hits":"1","order":"122","possible_hits":"1",},
{"lineNum":"   35","line":"    while hex.size < 2","class":"lineCov","hits":"1","order":"123","possible_hits":"1",},
{"lineNum":"   36","line":"      hex = \'0\' + hex","class":"lineCov","hits":"1","order":"231","possible_hits":"1",},
{"lineNum":"   37","line":"    end"},
{"lineNum":"   38","line":"    hex"},
{"lineNum":"   39","line":"  end"},
{"lineNum":"   40","line":""},
{"lineNum":"   41","line":"  # An utility tool to ensure hex keys are always 32 bytes;"},
{"lineNum":"   42","line":"  # it pads the number with leading zeros if it\'s shorter."},
{"lineNum":"   43","line":"  #"},
{"lineNum":"   44","line":"  # Parameters:"},
{"lineNum":"   45","line":"  # * `i` (`BigInt`): the integer to be formatted as padded hex byte string."},
{"lineNum":"   46","line":"  #"},
{"lineNum":"   47","line":"  # ```"},
{"lineNum":"   48","line":"  # Secp256k1::Util.to_padded_hex_32 BigInt.new 7"},
{"lineNum":"   49","line":"  # # => \"0000000000000000000000000000000000000000000000000000000000000007\""},
{"lineNum":"   50","line":"  # ```"},
{"lineNum":"   51","line":"  def self.to_padded_hex_32(i : BigInt)","class":"lineCov","hits":"2","order":"14","possible_hits":"2",},
{"lineNum":"   52","line":"    hex = i.to_s 16","class":"lineCov","hits":"1","order":"15","possible_hits":"1",},
{"lineNum":"   53","line":"    while hex.size < 64","class":"lineCov","hits":"1","order":"16","possible_hits":"1",},
{"lineNum":"   54","line":"      hex = \'0\' + hex","class":"lineCov","hits":"1","order":"176","possible_hits":"1",},
{"lineNum":"   55","line":"    end"},
{"lineNum":"   56","line":"    hex"},
{"lineNum":"   57","line":"  end"},
{"lineNum":"   58","line":""},
{"lineNum":"   59","line":"  # A helper function to generate 32 pseudo-random bytes within the elliptic"},
{"lineNum":"   60","line":"  # curve field size of `EC_ORDER_N`."},
{"lineNum":"   61","line":"  #"},
{"lineNum":"   62","line":"  # ```"},
{"lineNum":"   63","line":"  # Secp256k1::Util.new_private_key"},
{"lineNum":"   64","line":"  # # => \"b795cd2c5ce0cc632ca1f65e921b9c751b363e97fcaeec81c02a85b763448268\""},
{"lineNum":"   65","line":"  # ```"},
{"lineNum":"   66","line":"  def self.new_private_key","class":"lineCov","hits":"1","order":"283","possible_hits":"1",},
{"lineNum":"   67","line":"    key = -999","class":"lineCov","hits":"1","order":"284","possible_hits":"1",},
{"lineNum":"   68","line":"    until key > 0","class":"lineCov","hits":"2","order":"285","possible_hits":"2",},
{"lineNum":"   69","line":"      key = Random::Secure.hex 32","class":"lineCov","hits":"1","order":"286","possible_hits":"1",},
{"lineNum":"   70","line":"      key = BigInt.new key, 16","class":"lineCov","hits":"1","order":"287","possible_hits":"1",},
{"lineNum":"   71","line":"    end"},
{"lineNum":"   72","line":"    key % EC_ORDER_N","class":"lineCov","hits":"2","order":"288","possible_hits":"2",},
{"lineNum":"   73","line":"  end"},
{"lineNum":"   74","line":""},
{"lineNum":"   75","line":"  # Exports the compressed public key from an ec point without prefix."},
{"lineNum":"   76","line":"  #"},
{"lineNum":"   77","line":"  # The compressed public key without prefix is just the `x` coordinate"},
{"lineNum":"   78","line":"  # of the public key and **cannot** be recovered as full public key."},
{"lineNum":"   79","line":"  # This is just a helper function and should not be used unless you"},
{"lineNum":"   80","line":"  # know why you want to do this."},
{"lineNum":"   81","line":"  #"},
{"lineNum":"   82","line":"  # In most cases, you are looking for `public_key_compressed_prefix`."},
{"lineNum":"   83","line":"  #"},
{"lineNum":"   84","line":"  # Parameters:"},
{"lineNum":"   85","line":"  # * `p` (`ECPoint`): the public key point which shall be compressed."},
{"lineNum":"   86","line":"  #"},
{"lineNum":"   87","line":"  # ```"},
{"lineNum":"   88","line":"  # Secp256k1::Util.public_key_compressed my_public_key"},
{"lineNum":"   89","line":"  # # => \"d885aed4bcaf3a8c95a57e3be08caa1bd6a060a68b9795c03129073597fcb19a\""},
{"lineNum":"   90","line":"  # ```"},
{"lineNum":"   91","line":"  private def self.public_key_compressed(p : ECPoint)","class":"lineCov","hits":"2","order":"12","possible_hits":"2",},
{"lineNum":"   92","line":"    to_padded_hex_32 p.x","class":"lineCov","hits":"1","order":"13","possible_hits":"1",},
{"lineNum":"   93","line":"  end"},
{"lineNum":"   94","line":""},
{"lineNum":"   95","line":"  # Exports the compressed public key from an `ECPoint` with either the"},
{"lineNum":"   96","line":"  # prefix `\"02\"` or `\"03\"`."},
{"lineNum":"   97","line":"  #"},
{"lineNum":"   98","line":"  # The prefix can be later used to recover the `y` coordinate of the public key,"},
{"lineNum":"   99","line":"  # see `decode_compressed_public_key`. `Bitcoin` uses this format"},
{"lineNum":"  100","line":"  # to generate shorter addresses as compared to using uncompressed keys."},
{"lineNum":"  101","line":"  #"},
{"lineNum":"  102","line":"  # Parameters:"},
{"lineNum":"  103","line":"  # * `p` (`ECPoint`): the public key point which shall be compressed."},
{"lineNum":"  104","line":"  #"},
{"lineNum":"  105","line":"  # ```"},
{"lineNum":"  106","line":"  # Secp256k1::Util.public_key_compressed_prefix my_public_key"},
{"lineNum":"  107","line":"  # # => \"03d885aed4bcaf3a8c95a57e3be08caa1bd6a060a68b9795c03129073597fcb19a\""},
{"lineNum":"  108","line":"  # ```"},
{"lineNum":"  109","line":"  def self.public_key_compressed_prefix(p : ECPoint)","class":"lineCov","hits":"2","order":"9","possible_hits":"2",},
{"lineNum":"  110","line":"    prefix = p.y % 2 === 1 ? \"03\" : \"02\"","class":"lineCov","hits":"1","order":"10","possible_hits":"1",},
{"lineNum":"  111","line":"    \"#{prefix}#{public_key_compressed p}\"","class":"lineCov","hits":"1","order":"11","possible_hits":"1",},
{"lineNum":"  112","line":"  end"},
{"lineNum":"  113","line":""},
{"lineNum":"  114","line":"  # Exports the uncompressed public key from an `ECPoint` without prefix."},
{"lineNum":"  115","line":"  #"},
{"lineNum":"  116","line":"  # `Ethereum` uses this format to generate addresses. For prefixed"},
{"lineNum":"  117","line":"  # uncompressed public keys, see `public_key_uncompressed_prefix`."},
{"lineNum":"  118","line":"  #"},
{"lineNum":"  119","line":"  # Parameters:"},
{"lineNum":"  120","line":"  # * `p` (`ECPoint`): the public key point which shall be uncompressed."},
{"lineNum":"  121","line":"  #"},
{"lineNum":"  122","line":"  # ```"},
{"lineNum":"  123","line":"  # Secp256k1::Util.public_key_uncompressed my_public_key"},
{"lineNum":"  124","line":"  # # => \"d885aed4bcaf3a8c95a57e3be08caa1bd6a060a68b9795c03129073597fcb19a67299d1cf25955e9b6425583cbc33f4ab831f5a31ef88c7167e9eb714cc758a5\""},
{"lineNum":"  125","line":"  # ```"},
{"lineNum":"  126","line":"  def self.public_key_uncompressed(p : ECPoint)","class":"lineCov","hits":"2","order":"20","possible_hits":"2",},
{"lineNum":"  127","line":"    x = to_padded_hex_32 p.x","class":"lineCov","hits":"1","order":"21","possible_hits":"1",},
{"lineNum":"  128","line":"    y = to_padded_hex_32 p.y","class":"lineCov","hits":"1","order":"22","possible_hits":"1",},
{"lineNum":"  129","line":"    \"#{x}#{y}\"","class":"lineCov","hits":"1","order":"23","possible_hits":"1",},
{"lineNum":"  130","line":"  end"},
{"lineNum":"  131","line":""},
{"lineNum":"  132","line":"  # Exports the uncompressed public key from an `ECPoint` with prefix `\"04\"`."},
{"lineNum":"  133","line":"  #"},
{"lineNum":"  134","line":"  # `Bitcoin` uses this format to generate uncompressed addresses."},
{"lineNum":"  135","line":"  # For unprefixed public keys, see `public_key_uncompressed`."},
{"lineNum":"  136","line":"  #"},
{"lineNum":"  137","line":"  # Parameters:"},
{"lineNum":"  138","line":"  # * `p` (`ECPoint`): the public key point which shall be uncompressed."},
{"lineNum":"  139","line":"  #"},
{"lineNum":"  140","line":"  # ```"},
{"lineNum":"  141","line":"  # Secp256k1::Util.public_key_uncompressed_prefix my_public_key"},
{"lineNum":"  142","line":"  # # => \"04d885aed4bcaf3a8c95a57e3be08caa1bd6a060a68b9795c03129073597fcb19a67299d1cf25955e9b6425583cbc33f4ab831f5a31ef88c7167e9eb714cc758a5\""},
{"lineNum":"  143","line":"  # ```"},
{"lineNum":"  144","line":"  def self.public_key_uncompressed_prefix(p : ECPoint)","class":"lineCov","hits":"2","order":"18","possible_hits":"2",},
{"lineNum":"  145","line":"    \"04#{public_key_uncompressed p}\"","class":"lineCov","hits":"1","order":"19","possible_hits":"1",},
{"lineNum":"  146","line":"  end"},
{"lineNum":"  147","line":""},
{"lineNum":"  148","line":"  # Decodes a public key as `ECPoint` from a compressed public key string."},
{"lineNum":"  149","line":"  #"},
{"lineNum":"  150","line":"  # If unsure, `restore_public_key` should be used."},
{"lineNum":"  151","line":"  #"},
{"lineNum":"  152","line":"  # Parameters:"},
{"lineNum":"  153","line":"  # * `pub` (`String`): the public key in prefixed compressed format."},
{"lineNum":"  154","line":"  # * `prime` (`BigInt`): the prime number that shapes the field, default: `EC_PRIME_P`."},
{"lineNum":"  155","line":"  #"},
{"lineNum":"  156","line":"  # ```"},
{"lineNum":"  157","line":"  # Secp256k1::Util.decode_compressed_public_key \"03d885aed4bcaf3a8c95a57e3be08caa1bd6a060a68b9795c03129073597fcb19a\""},
{"lineNum":"  158","line":"  # ```"},
{"lineNum":"  159","line":"  #"},
{"lineNum":"  160","line":"  # Returns an `ECPoint` containing the public key."},
{"lineNum":"  161","line":"  #"},
{"lineNum":"  162","line":"  # Raises if compressed public key is malformed or comes with invalid prefix."},
{"lineNum":"  163","line":"  def self.decode_compressed_public_key(pub : String, prime = EC_PRIME_P)","class":"lineCov","hits":"2","order":"317","possible_hits":"2",},
{"lineNum":"  164","line":"    # Only proceed if we have one prefix byte and 32 coordinate bytes."},
{"lineNum":"  165","line":"    if pub.size === 66","class":"lineCov","hits":"1","order":"318","possible_hits":"1",},
{"lineNum":"  166","line":"      # The prefix is used to restore the `y`-coordinate."},
{"lineNum":"  167","line":"      prefix = pub[0, 2]","class":"lineCov","hits":"1","order":"319","possible_hits":"1",},
{"lineNum":"  168","line":"      if prefix === \"02\" || prefix === \"03\"","class":"lineCov","hits":"2","order":"320","possible_hits":"2",},
{"lineNum":"  169","line":"        # `x` is simply the coordinate."},
{"lineNum":"  170","line":"        x = BigInt.new pub[2, 64], 16","class":"lineCov","hits":"1","order":"321","possible_hits":"1",},
{"lineNum":"  171","line":""},
{"lineNum":"  172","line":"        # `y` is on our curve `(x^3 + 7) ^ ((p + 1) / 4) % p`"},
{"lineNum":"  173","line":"        a = x ** 3 % prime","class":"lineCov","hits":"1","order":"322","possible_hits":"1",},
{"lineNum":"  174","line":"        a = (a + 7) % prime","class":"lineCov","hits":"1","order":"323","possible_hits":"1",},
{"lineNum":"  175","line":"        e = ((prime + 1) // 4) % prime","class":"lineCov","hits":"1","order":"324","possible_hits":"1",},
{"lineNum":"  176","line":"        y = BigInt.new","class":"lineCov","hits":"1","order":"325","possible_hits":"1",},
{"lineNum":"  177","line":"        LibGMP.mpz_powm_sec(y, a, e, prime)","class":"lineCov","hits":"1","order":"326","possible_hits":"1",},
{"lineNum":"  178","line":""},
{"lineNum":"  179","line":"        # Check which of the two possible `y` values is to be used."},
{"lineNum":"  180","line":"        parity = prefix.to_i - 2","class":"linePartCov","hits":"1","order":"327","possible_hits":"2",},
{"lineNum":"  181","line":"        if y % 2 != parity","class":"lineCov","hits":"1","order":"328","possible_hits":"1",},
{"lineNum":"  182","line":"          y = -y % prime","class":"lineNoCov","hits":"0","possible_hits":"1",},
{"lineNum":"  183","line":"        end"},
{"lineNum":"  184","line":"        ECPoint.new x, y","class":"lineCov","hits":"2","order":"329","possible_hits":"2",},
{"lineNum":"  185","line":"      else"},
{"lineNum":"  186","line":"        raise \"invalid prefix for compressed public key: #{prefix}\"","class":"lineCov","hits":"1","order":"331","possible_hits":"1",},
{"lineNum":"  187","line":"      end"},
{"lineNum":"  188","line":"    else"},
{"lineNum":"  189","line":"      raise \"malformed compressed public key (invalid key size: #{pub.size})\"","class":"linePartCov","hits":"1","order":"330","possible_hits":"2",},
{"lineNum":"  190","line":"    end"},
{"lineNum":"  191","line":"  end"},
{"lineNum":"  192","line":""},
{"lineNum":"  193","line":"  # Decodes a public key as `ECPoint` from an uncompressed public key string."},
{"lineNum":"  194","line":"  #"},
{"lineNum":"  195","line":"  # If unsure, `restore_public_key` should be used."},
{"lineNum":"  196","line":"  #"},
{"lineNum":"  197","line":"  # Parameters:"},
{"lineNum":"  198","line":"  # * `pub` (`String`): the public key in any uncompressed format."},
{"lineNum":"  199","line":"  #"},
{"lineNum":"  200","line":"  # ```"},
{"lineNum":"  201","line":"  # Secp256k1::Util.decode_uncompressed_public_key \"04d885aed4bcaf3a8c95a57e3be08caa1bd6a060a68b9795c03129073597fcb19a67299d1cf25955e9b6425583cbc33f4ab831f5a31ef88c7167e9eb714cc758a5\""},
{"lineNum":"  202","line":"  # ```"},
{"lineNum":"  203","line":"  #"},
{"lineNum":"  204","line":"  # Returns an `ECPoint` containing the public key."},
{"lineNum":"  205","line":"  #"},
{"lineNum":"  206","line":"  # Raises if uncompressed public key is malformed."},
{"lineNum":"  207","line":"  private def self.decode_uncompressed_public_key(pub : String)","class":"lineCov","hits":"2","order":"308","possible_hits":"2",},
{"lineNum":"  208","line":"    # Remove the prefix as it\'s always `\"04\"` for uncompressed keys."},
{"lineNum":"  209","line":"    pub = pub[2, 128] if pub.size === 130","class":"lineCov","hits":"1","order":"309","possible_hits":"1",},
{"lineNum":"  210","line":""},
{"lineNum":"  211","line":"    # Only proceed if we have two times 32 bytes (`x`, `y`)."},
{"lineNum":"  212","line":"    if pub.size === 128","class":"lineCov","hits":"1","order":"310","possible_hits":"1",},
{"lineNum":"  213","line":"      x = BigInt.new pub[0, 64], 16","class":"lineCov","hits":"1","order":"311","possible_hits":"1",},
{"lineNum":"  214","line":"      y = BigInt.new pub[64, 64], 16","class":"lineCov","hits":"1","order":"312","possible_hits":"1",},
{"lineNum":"  215","line":"      ECPoint.new x, y","class":"lineCov","hits":"1","order":"313","possible_hits":"1",},
{"lineNum":"  216","line":"    else"},
{"lineNum":"  217","line":"      raise \"malformed uncompressed public key (invalid key size: #{pub.size})\"","class":"lineNoCov","hits":"0","possible_hits":"1",},
{"lineNum":"  218","line":"    end"},
{"lineNum":"  219","line":"  end"},
{"lineNum":"  220","line":""},
{"lineNum":"  221","line":"  # Detects public key type and tries to restore the `ECPoint` from it."},
{"lineNum":"  222","line":"  #"},
{"lineNum":"  223","line":"  # Parameters:"},
{"lineNum":"  224","line":"  # * `pub` (`String`): the public key in any format."},
{"lineNum":"  225","line":"  # * `prime` (`BigInt`): the prime number that shapes the field, default: `EC_PRIME_P`."},
{"lineNum":"  226","line":"  #"},
{"lineNum":"  227","line":"  # ```"},
{"lineNum":"  228","line":"  # Secp256k1::Util.restore_public_key \"d885aed4bcaf3a8c95a57e3be08caa1bd6a060a68b9795c03129073597fcb19a67299d1cf25955e9b6425583cbc33f4ab831f5a31ef88c7167e9eb714cc758a5\""},
{"lineNum":"  229","line":"  # ```"},
{"lineNum":"  230","line":"  #"},
{"lineNum":"  231","line":"  # Returns an `ECPoint` containing the public key."},
{"lineNum":"  232","line":"  #"},
{"lineNum":"  233","line":"  # Raises if public key format is unknown."},
{"lineNum":"  234","line":"  def self.restore_public_key(pub : String, prime = EC_PRIME_P)","class":"lineCov","hits":"4","order":"304","possible_hits":"4",},
{"lineNum":"  235","line":"    case pub.size","class":"lineCov","hits":"1","order":"305","possible_hits":"1",},
{"lineNum":"  236","line":"    when 130, 128","class":"lineCov","hits":"2","order":"306","possible_hits":"2",},
{"lineNum":"  237","line":"      decode_uncompressed_public_key pub","class":"lineCov","hits":"1","order":"307","possible_hits":"1",},
{"lineNum":"  238","line":"    when 66","class":"lineCov","hits":"2","order":"315","possible_hits":"2",},
{"lineNum":"  239","line":"      decode_compressed_public_key pub, prime","class":"lineCov","hits":"1","order":"316","possible_hits":"1",},
{"lineNum":"  240","line":"    else"},
{"lineNum":"  241","line":"      raise \"unknown public key format (invalid key size: #{pub.size})\"","class":"lineCov","hits":"2","order":"314","possible_hits":"2",},
{"lineNum":"  242","line":"    end"},
{"lineNum":"  243","line":"  end"},
{"lineNum":"  244","line":""},
{"lineNum":"  245","line":"  # Gets a public key from a private key."},
{"lineNum":"  246","line":"  #"},
{"lineNum":"  247","line":"  # This is basically a wrapper function to perform an elliptic curve"},
{"lineNum":"  248","line":"  # multiplication with the generator point `g` and a provided private key `priv`."},
{"lineNum":"  249","line":"  #"},
{"lineNum":"  250","line":"  # Parameters:"},
{"lineNum":"  251","line":"  # * `priv` (`BigInt`): the private key to be used."},
{"lineNum":"  252","line":"  #"},
{"lineNum":"  253","line":"  # ```"},
{"lineNum":"  254","line":"  # Secp256k1::Util.public_key_from_private BigInt.new(\"b795cd2c5ce0cc632ca1f65e921b9c751b363e97fcaeec81c02a85b763448268\", 16)"},
{"lineNum":"  255","line":"  # ```"},
{"lineNum":"  256","line":"  #"},
{"lineNum":"  257","line":"  # Returns an `ECPoint` containing the public key."},
{"lineNum":"  258","line":"  def self.public_key_from_private(priv : BigInt)","class":"lineCov","hits":"2","order":"28","possible_hits":"2",},
{"lineNum":"  259","line":"    Core.ec_mul EC_BASE_G, priv","class":"lineCov","hits":"1","order":"29","possible_hits":"1",},
{"lineNum":"  260","line":"  end"},
{"lineNum":"  261","line":"end"},
]};
var percent_low = 25;var percent_high = 75;
var header = { "command" : "run_coverage", "date" : "2021-12-13 12:03:11", "instrumented" : 57, "covered" : 55,};
var merged_data = [];