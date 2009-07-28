// Copyright 2009 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Decrypter is sample code showing the steps to decrypt and verify 64-bit
// values. It uses the Base 64 decoder in the OpenSSL library.

#include <endian.h>
#include <netinet/in.h>
#include <openssl/hmac.h>
#include <sys/time.h>
#include <iostream>
#include <string>

typedef int                 int32;
typedef long long           int64;
typedef unsigned int        uint32;
typedef unsigned long long  uint64;
typedef unsigned char       uchar;

// Definition of ntohll
inline uint64 ntohll(uint64 host_int) {
#if defined(__LITTLE_ENDIAN)
  return static_cast<uint64>(ntohl(static_cast<uint32>(host_int >> 32))) |
      (static_cast<uint64>(ntohl(static_cast<uint32>(host_int))) << 32);
#elif defined(__BIG_ENDIAN)
  return host_int;
#else
#error Could not determine endianness.
#endif
}

namespace {
using std::cerr;
using std::cout;
using std::endl;
using std::string;

// The following sizes are all in bytes.
const int32 kInitializationVectorSize = 16;
const int32 kCiphertextSize = 8;
const int32 kSignatureSize = 4;
const int32 kEncryptedValueSize =
    kInitializationVectorSize + kCiphertextSize + kSignatureSize;
const int32 kKeySize = 32;  // size of SHA-1 HMAC keys.
const int32 kHashOutputSize = 20;  // size of SHA-1 hash output.

// Retrieves the timestamp embedded in the initialization vector.
void GetTime(const char* initialization_vector, struct timeval* tv) {
  uint32 val;
  memcpy(&val, initialization_vector, sizeof(val));
  tv->tv_sec = htonl(val);
  memcpy(&val, initialization_vector + sizeof(val), sizeof(val));
  tv->tv_usec = htonl(val);
}

// Takes an unpadded base64 string and adds padding.
string AddPadding(const string& b64_string) {
  if (b64_string.size() % 4 == 3) {
    return b64_string + "=";
  } else if (b64_string.size() % 4 == 2) {
    return b64_string + "==";
  }
  return b64_string;
}

// Adapted from http://www.openssl.org/docs/crypto/BIO_f_base64.html
// Takes a web safe base64 encoded string (RFC 3548) and decodes it.
// Normally, web safe base64 strings have padding '=' replaced with '.',
// but we will not pad the ciphertext. We add padding here because
// openssl has trouble with unpadded strings.
string B64Decode(const string& encoded) {
  string padded = AddPadding(encoded);
  // convert from web safe -> normal base64.
  int32 index = -1;
  while ((index = padded.find_first_of('-', index + 1)) != string::npos) {
    padded[index] = '+';
  }
  index = -1;
  while ((index = padded.find_first_of('_', index + 1)) != string::npos) {
    padded[index] = '/';
  }

  // base64 decode using openssl library.
  const int32 kOutputBufferSize = 256;
  char output[kOutputBufferSize];

  BIO* b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  BIO* bio = BIO_new_mem_buf(const_cast<char*>(padded.data()),
                             padded.length());
  bio = BIO_push(b64, bio);
  int32 out_length = BIO_read(bio, output, kOutputBufferSize);
  BIO_free_all(bio);
  return string(output, out_length);
}

// The actual decryption method:
// Decrypts the ciphertext using the encryption key and verifies the integrity
// bits with the integrity key. The encrypted format is:
// {initialization_vector (16 bytes)}{ciphertext (8 bytes)}{integrity (4 bytes)}
// The value is encrypted as
// <value xor HMAC(encryption_key, initialization_vector)> so
// decryption calculates HMAC(encryption_key, initialization_vector) and xor's
// with the ciphertext to reverse the encryption. The integrity stage takes 4
// bytes of <HMAC(integrity_key, value||initialization_vector)> where || is
// concatenation.
// If Decrypt returns true, value contains the value encrypted in ciphertext.
// If Decrypt returns false, the value could not be decrypted (the signature
// did not match).
bool Decrypt(const string& encrypted_value, const string& encryption_key,
    const string& integrity_key, int64* value) {
  // Compute plaintext.
  const uchar* initialization_vector = (uchar*)encrypted_value.data();
  const uchar* ciphertext_bytes =
      initialization_vector + kInitializationVectorSize;
  const uchar* signature = ciphertext_bytes + kCiphertextSize;

  uint32 pad_size = kHashOutputSize;
  uchar encryption_pad[kHashOutputSize];
  if (!HMAC(EVP_sha1(), encryption_key.data(), encryption_key.length(),
            initialization_vector, kInitializationVectorSize, encryption_pad,
            &pad_size)) {
    std::cerr << "Error: encryption HMAC failed" << endl;
    return false;
  }

  uchar plaintext_bytes[kCiphertextSize];
  for (int32 i = 0; i < kCiphertextSize; ++i) {
    plaintext_bytes[i] = encryption_pad[i] ^ ciphertext_bytes[i];
  }
  memcpy(value, plaintext_bytes, kCiphertextSize);
  *value = ntohll(*value);  // Switch to host byte order.

  // Verify integrity bits.
  uint32 integrity_hash_size = kHashOutputSize;
  unsigned char integrity_hash[kHashOutputSize];
  const int32 kInputMessageSize = kCiphertextSize + kInitializationVectorSize;
  unsigned char input_message[kInputMessageSize];
  memcpy(input_message, plaintext_bytes, kCiphertextSize);
  memcpy(input_message + kCiphertextSize,
         initialization_vector,
         kInitializationVectorSize);

  if (!HMAC(EVP_sha1(), integrity_key.data(), integrity_key.length(),
      input_message, kInputMessageSize, integrity_hash,
      &integrity_hash_size)) {
    cerr << "Error: integrity HMAC failed" << endl;
    return false;
  }

  return memcmp(integrity_hash, signature, kSignatureSize) == 0;
}

}  // namespace

// An example program that decodes the hardcoded ciphertext using hardcoded
// keys. First it base64 decodes the encrypted value, then it calls Decrypt to
// decrypt the ciphertext and verify its integrity.
int main(int argc, char** argv) {
  const char kEncryptionKey[] = {
      0xb0, 0x8c, 0x70, 0xcf, 0xbc, 0xb0, 0xeb, 0x6c, 0xab, 0x7e, 0x82, 0xc6,
      0xb7, 0x5d, 0xa5, 0x20, 0x72, 0xae, 0x62, 0xb2, 0xbf, 0x4b, 0x99, 0x0b,
      0xb8, 0x0a, 0x48, 0xd8, 0x14, 0x1e, 0xec, 0x07
  };
  const char kIntegrityKey[] = {
      0xbf, 0x77, 0xec, 0x55, 0xc3, 0x01, 0x30, 0xc1, 0xd8, 0xcd, 0x18, 0x62,
      0xed, 0x2a, 0x4c, 0xd2, 0xc7, 0x6a, 0xc3, 0x3b, 0xc0, 0xc4, 0xce, 0x8a,
      0x3d, 0x3b, 0xbd, 0x3a, 0xd5, 0x68, 0x77, 0x92
  };
  string encryption_key(kEncryptionKey, kKeySize);
  string integrity_key(kIntegrityKey, kKeySize);

  // This is an example of the encrypted data. It has a fixed length of 38
  // characters. The two padding characters are removed. It decodes to a string
  // of 28 bytes. The decrypted value should be 709959680.
  const string kB64EncodedValue("SjpvRwAB4kB7jEpgW5IA8p73ew9ic6VZpFsPnA");
  string encrypted_value = B64Decode(kB64EncodedValue);
  if (encrypted_value.size() != kEncryptedValueSize) {
    std::cerr << "Error: unexpected ciphertext length: "
              << encrypted_value.size() << endl;
    return 1;
  }

  int64 value = 0;
  bool success =
      Decrypt(encrypted_value, encryption_key, integrity_key, &value);
  if (success) {
    cout << "The value is:   " << value << endl;
    struct timeval tv;
    GetTime(encrypted_value.data(), &tv);
    struct tm tm;
    localtime_r(&tv.tv_sec, &tm);
    printf("Sent on %04d-%02d-%02d|%02d:%02d:%02d.%06ld\n",
           tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
           tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_usec);
  } else {
    cout << "Failed to decrypt value." << endl;
  }
  return 0;
}
