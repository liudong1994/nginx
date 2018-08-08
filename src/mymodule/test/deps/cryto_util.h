
#ifndef _CRYTO_UTIL_H_
#define _CRYTO_UTIL_H_

#include <openssl/md5.h>
#include <openssl/hmac.h>  

const char base64_code[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
const char base64_rcode[] = {
     65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 
     65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 
     65, 65, 62, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 62, 65, 
     65, 65, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 65, 65, 
     65, 64, 65, 65, 65,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 
     10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 
     25, 65, 65, 65, 65, 65, 65, 26, 27, 28, 29, 30, 31, 32, 33, 
     34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 
     49, 50, 51, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 
     65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 
     65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 
     65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 
     65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 
     65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 
     65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 
     65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 
     65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65
};

class Base64Util {
    private:
        Base64Util() {}

    public:
        static bool encode(const char *in, const size_t len, 
                std::string *out) {

            if (!in || !out) {
                return false;
            }

            out->clear();
            out->reserve((len / 3 + 1) * 4);
            const char *s = in;
            size_t n = len;

            while (n > 2) {
                *out += base64_code[s[0] >> 2 & 0x3f];
                *out += base64_code[(s[0] << 4 & 0x30) | (s[1] >> 4 & 0x0f)];
                *out += base64_code[(s[1] << 2 & 0x3c) | (s[2] >> 6 & 0x03)];
                *out += base64_code[s[2] & 0x3f];
                s += 3;
                n -= 3;
            }

            if (n) {
                *out += base64_code[s[0] >> 2 & 0x3f];
                if (n == 1) {
                    *out += base64_code[s[0] << 4 & 0x30];
                    *out += base64_code[64];
                } else {
                    *out += base64_code[(s[0] << 4 & 0x30) | (s[1] >> 4 & 0x0f)];
                    *out += base64_code[s[1] << 2 & 0x3c];
                }
                *out += base64_code[64];
            }

            return true;
        }

        static bool decode(const char *in, const size_t len,
                std::string *out) {
            if (!in || ! out || len % 4 != 0) {
                return false;
            }

            out->clear();
            out->reserve((len / 4 + 1) * 3);
            const unsigned char *s = (const unsigned char *)in;
            size_t n = len;

            while (n > 4) {
                *out += (base64_rcode[s[0]] << 2 & 0xfc) | (base64_rcode[s[1]] >> 4 & 0x03);
                *out += (base64_rcode[s[1]] << 4 & 0xf0) | (base64_rcode[s[2]] >> 2 & 0x0f);
                *out += (base64_rcode[s[2]] << 6 & 0xc0) | (base64_rcode[s[3]] & 0x3f);
                s += 4;
                n -= 4;
            }

            //n == 4
            if (base64_rcode[s[1]] < 64) {
                *out += (base64_rcode[s[0]] << 2 & 0xfc) | (base64_rcode[s[1]] >> 4 & 0x03);
            }
            if (base64_rcode[s[2]] < 64) {
                *out += (base64_rcode[s[1]] << 4 & 0xf0) | (base64_rcode[s[2]] >> 2 & 0x0f);
            }
            if (base64_rcode[s[3]] < 64) {
                *out += (base64_rcode[s[2]] << 6 & 0xc0) | (base64_rcode[s[3]] & 0x3f);
            }
        
            return true;
        }
};

class XORUtil {
    private:
        XORUtil() {}

    public:
        static bool exec(const char *in, const size_t len,
                const char *key, const size_t key_len, std::string *out, const size_t pos = 0) {
            if (!in || !key || !out || !len || !key_len) {
                return false;
            }

            out->resize(len);
            for (size_t i = pos; i < pos + len; ) {
                for (size_t j = 0; i < pos + len && j < key_len; ++i, ++j) {
                    (*out)[i % len] = in[i] ^ key[j];
                }
            }

            return true;
        }

};

class MD5Util {
    public:
        MD5Util() = delete;

    public:
        static bool md5exec(const char *str, const size_t len, std::string *res) {
            if (!str) {
                return false;
            }
            unsigned char buffer[16] = {0};
            MD5((const unsigned char*)str, len, buffer);

            res->append((char *)buffer, 16);
            return true;
        }
};

class HMACUtil {
    public:
        HMACUtil() = delete;

    public:
        static bool SHA1(const char *in, const size_t len,
               const char *key, const size_t key_len, std::string *out) {
            if (!in || !key || !out || !len || !key_len) {
                return false;
            }

            unsigned char digest[EVP_MAX_MD_SIZE] = {'\0'};
            unsigned int digest_len = 0;
            HMAC(EVP_sha1(), key, key_len, (const unsigned char *)in, len, 
                    digest, &digest_len);
            out->assign((const char *)digest, digest_len);

            return true;
        }
};

#endif /* _CRYTO_UTIL_H_ */
