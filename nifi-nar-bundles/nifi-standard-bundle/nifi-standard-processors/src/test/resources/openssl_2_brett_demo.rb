#!/usr/bin/env ruby

# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'openssl'

# This script will encrypt a password in a format that NiFi can decrypt it, using the master key "password" "mybigsecretkey", no salt, and PBEWITHMD5AND256BITAES-CBC-OPENSSL as the KDF

def bin_to_hex(s)
  s.each_byte.map { |b| b.to_s(16).rjust(2, '0') }.join
end

master_passphrase = "mybigsecretkey" # Chosen as example -- not ideal
puts "Master passphrase: #{master_passphrase}"

plaintext = "password123" # Chosen as example -- not ideal
puts "Password to be encrypted: #{plaintext}"

# Cipher text from Jasypt
cipher_text = "0123456789ABCDEFFEDCBA9876543210532EC188A9385763A5CE1240636EC593"
# master_salt = cipher_text.scan(/../).map(&:hex)
master_salt = cipher_text[0..31]
# master_salt = '00000000'
cipher_text = cipher_text[32..-1]
puts "Salt: #{master_salt} 16"
puts "  CT: #{cipher_text} 16"

cipher = OpenSSL::Cipher.new 'AES-256-CBC'
cipher.decrypt

# If the salt was 8 bytes, this would work, but NiFi Jasypt uses a 16 byte salt
# cipher.pkcs5_keyivgen master_passphrase, master_salt, 1000, OpenSSL::Digest::MD5.new

# Do it the hard way

# Run MD5(passphrase + salt, 1000)
md5 = OpenSSL::Digest::MD5.new
temp_mk = master_passphrase + master_salt
puts "Temp MK: #{temp_mk}"
iterations = 1
iterations.times do
  temp_mk = md5.digest(temp_mk)
end

d_0 = ''
puts "D_0: #{d_0}"
d_1 = bin_to_hex(md5.digest(master_passphrase + master_salt))
puts "D_1: #{d_1}"
d_2 = bin_to_hex(md5.digest(d_1 + master_passphrase + master_salt))
puts "D_2: #{d_2}"
d_3 = bin_to_hex(md5.digest(d_2 + master_passphrase + master_salt))
puts "D_3: #{d_3}"

key = d_0 + d_1 + d_2 + d_3
puts "Key: #{key}"

# prev = ''
# current = temp_mk
#
# while current.length < 32
#   puts "   prev: #{bin_to_hex(prev)} #{prev.length}"
#   puts "current: #{bin_to_hex(current)} #{current.length}"
#   current = prev + md5.digest(current + master_passphrase + master_salt)
#   prev = current
#
#   puts "n  prev: #{bin_to_hex(prev)} #{prev.length}"
#   puts "n  curr: #{bin_to_hex(current)} #{current.length}"
# end

master_key = key
puts "After #{iterations} iterations, the master key is #{master_key}"
key=master_key[0..63]
iv=master_key[64..-1]
puts "Key: #{key}"
puts " IV: #{iv}"

cipher.key = key
cipher.iv = iv

# iv = cipher.iv
# key = cipher.key

puts ""

# puts "  IV: #{bin_to_hex(iv)} #{iv.length}"
# puts " Key: #{bin_to_hex(key)} #{key.length}"

# Now encrypt the data:

decrypted = cipher.update cipher_text
decrypted << cipher.final
puts "Plaintext length: #{decrypted.length}"
puts "Plaintext: #{bin_to_hex(decrypted)}"