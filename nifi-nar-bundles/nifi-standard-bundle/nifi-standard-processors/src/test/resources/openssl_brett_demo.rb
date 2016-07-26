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

# Cheat way to get a deterministic salt of 16 bytes
master_salt = '0123456789ABCDEFFEDCBA9876543210'

cipher = OpenSSL::Cipher.new 'AES-256-CBC'
cipher.encrypt

# If the salt was 8 bytes, this would work, but NiFi Jasypt uses a 16 byte salt
# cipher.pkcs5_keyivgen 'mybigsecretkey', master_salt, 1000, OpenSSL::Digest::MD5.new

# Do it the hard way

# Run MD5(passphrase + salt, 1000)
md5 = OpenSSL::Digest::MD5.new
prev = ''
current = ''
iterations = 1000
iterations.times do
  while current.length < 32
    # puts "   prev: #{bin_to_hex(prev)} #{prev.length}"
    # puts "current: #{bin_to_hex(current)} #{current.length}"
    current = prev + md5.digest(prev + master_passphrase + master_salt)
    prev = current
  end
end

master_key = bin_to_hex(current)
puts "After #{iterations} iterations, the master key is #{master_key}"
key=bin_to_hex(master_key)[0..31]
iv=bin_to_hex(master_key)[32..63]
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

encrypted = cipher.update plaintext
encrypted << cipher.final
puts "Cipher text length: #{encrypted.length}"
puts "Cipher text: #{bin_to_hex(encrypted)}"

complete_cipher_text = master_salt + bin_to_hex(encrypted)
puts "Complete cipher text length: #{complete_cipher_text.length / 2}"
puts "Complete cipher text: enc{#{complete_cipher_text}}"
