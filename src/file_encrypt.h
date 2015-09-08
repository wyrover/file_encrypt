/* Copyright http://www.gokulab.com. All rights reserved.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to
* deal in the Software without restriction, including without limitation the
* rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
* sell copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
* FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
* IN THE SOFTWARE.
*/

#ifndef FILE_ENCRYPT_H
#define FILE_ENCRYPT_H

#include <string>
#include <cassert>
#include <openssl/pem.h>
#include <openssl/rsa.h>


class FileEncrypt {
public:
  FileEncrypt() {
    public_key_ = private_key_ = NULL;
  }


  int LoadPublicKey(const std::string& fpath) {
    FILE* handle = fopen(fpath.c_str(), "r");
    do {
      if (!handle) { break; }
      public_key_ = PEM_read_RSA_PUBKEY(handle, NULL, NULL, NULL);
    } while (false);
    if (handle) { fclose(handle); }
    return public_key_ == NULL;
  }


  int LoadPrivateKey(const std::string& fpath) {
    FILE* handle = fopen(fpath.c_str(), "r");
    do {
      if (!handle) { break; }
      private_key_ = PEM_read_RSAPrivateKey(handle, NULL, NULL, NULL);
    } while (false);
    if (handle) { fclose(handle); }
    return private_key_ == NULL;
  }


  int EncryptFile(const std::string& old_name, const std::string& new_name) {
    unsigned char *to = NULL, *from = NULL;
    int ret = -1;
    if (!public_key_) { return -1; }
    FILE* old_handle = fopen(old_name.c_str(), "rb");
    if (!old_handle) { return -1; }
    FILE* new_handle = fopen(new_name.c_str(), "wb");
    if (!new_handle) { goto __cleanup_old_handle; }
    const int rsa_sz = RSA_size(public_key_);
    to = (unsigned char*)malloc(rsa_sz);
    if (!to) { goto __cleanup_new_handle; }
    const int block_sz = rsa_sz - 11;
    from = (unsigned char*)malloc(block_sz);
    if (!from) { goto __cleanup_to; }
    while (!feof(old_handle)) {
      const size_t sz = fread(from, 1, block_sz, old_handle);
      if (ferror(old_handle)) { goto __cleanup_to; }
      int encrypted_sz = RSA_public_encrypt(sz, from, to, public_key_, 
                                            RSA_PKCS1_PADDING);
      if (-1 == encrypted_sz) { goto __cleanup_to; }
      if (fwrite(to, 1, encrypted_sz, new_handle) != encrypted_sz) {
        goto __cleanup_to;
      }
    }
    ret = 0;
  __cleanup_to:
    free(to);
  __cleanup_new_handle:
    fclose(new_handle);
  __cleanup_old_handle:
    fclose(old_handle);
    return ret;
  }


  int DecryptFile(const std::string& old_name, const std::string& new_name) {
    unsigned char *to = NULL, *from = NULL;
    int ret = -1;
    if (!private_key_) { return -1; }
    FILE* old_handle = fopen(old_name.c_str(), "rb");
    if (!old_handle) { return -1; }
    FILE* new_handle = fopen(new_name.c_str(), "wb");
    if (!new_handle) { goto __cleanup_old_handle; }
    const int rsa_sz = RSA_size(private_key_);
    to = (unsigned char*)malloc(rsa_sz);
    if (!to) { goto __cleanup_new_handle; }
    const int block_sz = rsa_sz;
    from = (unsigned char*)malloc(block_sz);
    if (!from) { goto __cleanup_to; }
    while (!feof(old_handle)) {
      const size_t sz = fread(from, 1, block_sz, old_handle);
      if (ferror(old_handle)) { goto __cleanup_to; }
      int decrypted_sz = RSA_private_decrypt(sz, from, to, private_key_,
                                             RSA_PKCS1_PADDING);
      if (-1 == decrypted_sz) { goto __cleanup_to; }
      if (fwrite(to, 1, decrypted_sz, new_handle) != decrypted_sz) {
        goto __cleanup_to;
      }
    }
    ret = 0;
  __cleanup_to:
    free(to);
  __cleanup_new_handle:
    fclose(new_handle);
  __cleanup_old_handle:
    fclose(old_handle);
    return ret;
  }


  bool IsFileEncrypted(const std::string& fpath) {
    return true;
  }

private:
  RSA* public_key_, *private_key_;
};

#endif // FILE_ENCRYPT_H
