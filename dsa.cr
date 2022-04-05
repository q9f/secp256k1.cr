require "./src/secp256k1"
include Secp256k1

# ```
# ```
# Num.new(Bytes[137]).to_zpadded_bytes
# # => Bytes[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 137]
# ```

# ```
# Key.new(Num.new "3ccf84820c20d5e8c536ba84c52ba410375b29b1812b5f7e722445c969a0fb30").private_hex
# # => "3ccf84820c20d5e8c536ba84c52ba410375b29b1812b5f7e722445c969a0fb30"
# ```

# ```
# Key.new(Num.new "3ccf84820c20d5e8c536ba84c52ba410375b29b1812b5f7e722445c969a0fb30").private_bytes
# # => Bytes[60, 207, 132, 130, 12, 32, 213, 232, 197, 54, 186, 132, 197, 43, 164, 16, 55, 91, 41, 177, 129, 43, 95, 126, 114, 36, 69, 201, 105, 160, 251, 48]
# ```

# ```
# Key.new(Num.new "3ccf84820c20d5e8c536ba84c52ba410375b29b1812b5f7e722445c969a0fb30").public_hex_compressed
# # => "02cd4a8712ee6efc15b5abe37c0dbfa979d89c427d3fe24b076008decefe94dba2"
# ```

# ```
# Key.new(Num.new "3ccf84820c20d5e8c536ba84c52ba410375b29b1812b5f7e722445c969a0fb30").public_bytes_compressed
# # => Bytes[2, 205, 74, 135, 18, 238, 110, 252, 21, 181, 171, 227, 124, 13, 191, 169, 121, 216, 156, 66, 125, 63, 226, 75, 7, 96, 8, 222, 206, 254, 148, 219, 162]
# ```

# ```
# a = Num.new
# a.hex
# # => "ea678c668356d16d8bf5c69f95c1055e39bd24174605f64846e27c3ae6a88d81"
#
# i = Curve.mod_inv a
# i.hex
# # => "2901bbb12fcb64e9887e699e69e6b0b3811db18f6b4f94dfb26084e5cb38cac7"
# ```

# p = Point.new Num.new "5cb1eec17e38b004a8fd90fa8e423432430f60d76c30bb33f4091243c029e86d"
# Curve.double p
# # => #<Secp256k1::Point:0x7f58a244e860
#

# ```
# ctx = Context.new
# r = Num.new "c4079db44240b7afe94985c69fc89602e33629fd9b8623d711c30ce6378b33df"
# s = Num.new "6842c1b63c94bdb8e4f5ae88fb65f7a98b77b197c8323004fb47ef57fab29053"
# v = Num.new "00"
# sig = Signature.new r, s, v
# hash = Util.sha256 "Henlo, Wordl"
# publ = Point.new "0416008a369439f1a8a75cf974860bed5b10180518d6b1dd3ac847f423fd375d6aa29474394f0cd79d2ea543507d069e97339284f01bdbfd27392daec0ec553816"
# ctx.verify sig, hash, publ
# # => true
# ```
