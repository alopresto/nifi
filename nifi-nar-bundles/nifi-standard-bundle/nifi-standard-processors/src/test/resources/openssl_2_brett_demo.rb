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
# cipher_text = "0123456789ABCDEFFEDCBA9876543210532EC188A9385763A5CE1240636EC593"
cipher_text = "000000000000000000000000000000001338F2F1F5C019B1BE686450D5937C52"
# cipher_text = "00000000000000000000000000000000564158070cf7aab289574d476c5b9416"
# master_salt = cipher_text.scan(/../).map(&:hex)
master_salt = cipher_text[0..31]
# master_salt = '00000000'
cipher_text = cipher_text[32..-1]
puts "Salt: #{master_salt} 16"
puts "  CT: #{cipher_text} 16"

cipher = OpenSSL::Cipher.new 'AES-256-CBC'

# Sanity check
cipher.encrypt

# hex_key = '00' * 32
# hex_iv = '00' * 16

hex_key ='41c5ab2857ce071e998fe00744e0bb6196069075ff1bdc65962cd73eb4113409'
hex_iv = '2e56cd6c3dc4f81129e2f56363586dc2'

puts "Encryption  IV: #{hex_iv} #{hex_iv.length / 2}"
puts "Encryption Key: #{hex_key} #{hex_key.length / 2}"

key = [hex_key].pack('H*')
iv = [hex_iv].pack('H*')

cipher.key = key
cipher.iv = iv

# Now encrypt the data:

encrypted = cipher.update plaintext
encrypted << cipher.final
puts "Sanity cipher text length: #{encrypted.length}"
puts "Sanity cipher text: #{bin_to_hex(encrypted)}"

cipher.decrypt

cipher.key = key
cipher.iv = iv

# Now decrypt the data:

decrypted = cipher.update encrypted
decrypted << cipher.final
puts "Sanity plaintext length: #{decrypted.length}"
puts "Sanity plaintext: #{decrypted}"

cipher.decrypt

# If the salt was 8 bytes, this would work, but NiFi Jasypt uses a 16 byte salt
# cipher.pkcs5_keyivgen master_passphrase, master_salt, 1000, OpenSSL::Digest::MD5.new

# Do it the hard way
iterations = 1000

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

puts ""
puts "Output of EVP_BytesToKey"
puts "Raw  IV: #{bin_to_hex iv.join}"
puts "Raw key: #{bin_to_hex key.join}"

puts ""

hex_iv = bin_to_hex iv.join.unpack("c*").pack("c*")
hex_key = bin_to_hex key.join.unpack("c*").pack("c*")

# hex_key ='41c5ab2857ce071e998fe00744e0bb6196069075ff1bdc65962cd73eb4113409'
# hex_iv = '2e56cd6c3dc4f81129e2f56363586dc2'

puts "  IV: #{hex_iv} #{iv.length}"
puts " Key: #{hex_key} #{key.length}"

key = [hex_key].pack('H*')
iv = [hex_iv].pack('H*')

cipher.key = key
cipher.iv = iv

# Now decrypt the data:

decrypted = cipher.update [cipher_text].pack('H*')
decrypted << cipher.final
puts "Plaintext length: #{decrypted.length}"
puts "Plaintext: #{decrypted}"