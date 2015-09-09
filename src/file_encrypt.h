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
#include <vector>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "data_encrypt.h"


class FileEncrypt {
public:
  FileEncrypt() {
  }


  int LoadPublicKey(const std::string& fpath) {
    return data_encrypt_.LoadPublicKey(fpath);
  }


  int LoadPrivateKey(const std::string& fpath) {
    return data_encrypt_.LoadPrivateKey(fpath);
  }


  int EncryptFile(const std::string& old_name, const std::string& new_name) {
    int ret = -1;
    const int rsa_sz = RSA_size(data_encrypt_.GetPublicKey());
    std::vector<unsigned char> from(rsa_sz - 11), to(rsa_sz);
    if (!data_encrypt_.GetPublicKey()) { return -1; }
    FILE* old_handle = fopen(old_name.c_str(), "rb");
    if (!old_handle) { return -1; }
    FILE* new_handle = fopen(new_name.c_str(), "wb");
    if (!new_handle) { goto __cleanup_old_handle; }
    while (!feof(old_handle)) {
      const size_t sz = fread(&from[0], 1, from.size(), old_handle);
      if (ferror(old_handle)) { goto __cleanup_new_handle; }
      if (sz == 0) { continue; }
      int ret = data_encrypt_.EncryptData(&from[0], sz, &to[0], to.size());
      assert(!ret);
      if (ret) { goto __cleanup_new_handle; }
      if (fwrite(&to[0], 1, rsa_sz, new_handle) != rsa_sz) {
        goto __cleanup_new_handle;
      }
    }
    ret = 0;
  __cleanup_new_handle:
    fclose(new_handle);
  __cleanup_old_handle:
    fclose(old_handle);
    return ret;
  }


  int DecryptFile(const std::string& old_name, const std::string& new_name) {
    if (!data_encrypt_.GetPrivateKey()) { return -1; }
    int ret = -1;
    const int rsa_sz = RSA_size(data_encrypt_.GetPrivateKey());
    std::vector<unsigned char> from(rsa_sz), to(rsa_sz - 11);
    FILE* old_handle = fopen(old_name.c_str(), "rb");
    if (!old_handle) { return -1; }
    FILE* new_handle = fopen(new_name.c_str(), "wb");
    if (!new_handle) { goto __cleanup_old_handle; }
    while (!feof(old_handle)) {
      const size_t sz = fread(&from[0], 1, from.size(), old_handle);
      if (ferror(old_handle)) { goto __cleanup_new_handle; }
      if (sz == 0) { continue; }
      int decrypt_sz = data_encrypt_.DecryptData(&from[0], sz, &to[0], to.size());
      std::cout << decrypt_sz << std::endl;
      if (-1 == decrypt_sz) { goto __cleanup_new_handle; }
      if (fwrite(&to[0], 1, decrypt_sz, new_handle) != decrypt_sz) {
        goto __cleanup_new_handle;
      }
    }
    ret = 0;
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
  DataEncrypt data_encrypt_;
};

#endif // FILE_ENCRYPT_H
