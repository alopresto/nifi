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

master_salt = '0123456789ABCDEFFEDCBA9876543210'
# master_salt = '00000000000000000000000000000000'
puts "Salt: #{master_salt} 16"

cipher = OpenSSL::Cipher.new 'AES-256-CBC'
cipher.encrypt

# If the salt was 8 bytes, this would work, but NiFi Jasypt uses a 16 byte salt
# cipher.pkcs5_keyivgen master_passphrase, master_salt, 1, OpenSSL::Digest::MD5.new

# Do it the hard way
def evp_bytes_to_key(key_len, iv_len, md, salt, data, count)
  key = ''.bytes
  key_ix = 0
  iv = ''.bytes
  iv_ix = 0
  md_buf = ''.bytes
  n_key = key_len
  n_iv = iv_len
  i = 0
  salt_length = salt.length
  if data == nil
    return [key, iv]
  end
  add_md = 0
  while true
    md.reset
    if add_md > 0
      md.update md_buf
    end
    add_md += 1
    md.update data
    if nil != salt
      md.update salt[0..salt_length-1]
    end
    md_buf = md.digest
    (1..count-1).each do
      md.reset
      md.update md_buf
      md_buf = md.digest
    end
    i = 0
    if n_key > 0
      while true
        if n_key == 0
          break
        end
        if i == md_buf.length
          break
        end
        key[key_ix] = md_buf[i]
        key_ix += 1
        n_key -= 1
        i += 1
      end
    end
    if n_iv > 0 && i != md_buf.length
      while true
        if n_iv == 0
          break
        end
        if i == md_buf.length
          break
        end
        iv[iv_ix] = md_buf[i]
        iv_ix += 1
        n_iv -= 1
        i += 1
      end
    end
    if n_key == 0 && n_iv == 0
      break
    end
  end
  (0..md_buf.length-1).each do |j|
    md_buf[j] = '0'
  end
  [key, iv]
end

iterations = 1
(key, iv) = evp_bytes_to_key cipher.key_len, cipher.iv_len, OpenSSL::Digest::MD5.new, [master_salt].pack('H*'), master_passphrase, iterations

# The key and IV are byte arrays, so join them to create strings
key = key.join
iv = iv.join

hex_key = bin_to_hex key
hex_iv = bin_to_hex   iv

puts ""
puts "Output of EVP_BytesToKey"
puts "Hex key: #{hex_key} #{key.length}"
puts "Hex  IV: #{hex_iv} #{iv.length}"

puts ""

cipher.key = key
cipher.iv = iv

# Now encrypt the data

encrypted = cipher.update plaintext
encrypted << cipher.final
hex_encrypted = bin_to_hex encrypted
puts "Cipher text length: #{encrypted.length}"
puts "Cipher text: #{hex_encrypted}"

puts "Populate flow.xml with this: enc{#{master_salt}#{hex_encrypted}}"