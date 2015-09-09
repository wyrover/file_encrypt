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

#ifndef DATA_ENCRYPT_H
#define DATA_ENCRYPT_H

#include <string>
#include <cassert>
#include <openssl/pem.h>
#include <openssl/rsa.h>

class DataEncrypt {
public:
  DataEncrypt() {
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


  int EncryptData(const void* src, size_t src_sz, void* dst, size_t dst_sz) const {
    const size_t rsa_sz = RSA_size(public_key_);
    assert(src_sz <= rsa_sz - 11);
    assert(dst_sz == rsa_sz);
    if (!public_key_) { return -1; }
    int encrypted_sz = RSA_public_encrypt(src_sz, (const unsigned char*)src, 
                                          (unsigned char*)dst, public_key_,
                                          RSA_PKCS1_PADDING);
    if (-1 == encrypted_sz) { return -1; }
    assert(encrypted_sz == rsa_sz);
    return 0;
  }


  int DecryptData(const void* src, size_t src_sz, void* dst, size_t dst_sz) const {
    const size_t rsa_sz = RSA_size(private_key_);
    assert(src_sz == rsa_sz);
    assert(dst_sz == rsa_sz - 11);
    if (!private_key_) { return -1; }
    int decrypted_sz = RSA_private_decrypt(src_sz, (const unsigned char*)src, 
                                           (unsigned char*)dst, private_key_,
                                           RSA_PKCS1_PADDING);
    if (-1 == decrypted_sz) { return -1; }
    return decrypted_sz;
  }

  RSA* GetPublicKey() const { return public_key_; }
  
  RSA* GetPrivateKey() const { return private_key_; }

private:
  RSA* public_key_, *private_key_;
};

#endif // DATA_ENCRYPT_H
