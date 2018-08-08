#ifndef _STR_UTIL_H_
#define _STR_UTIL_H_

#include <string>
#include <vector>
#include <unordered_set>
#include "cryto_util.h"     // split_str_and_base64_set

class CStrUtil
{
private:
    CStrUtil() {}

public:
    static void split_str(const std::string &s, const char delim, std::vector<std::string> *v) {
        if (s.empty() || !v) {
            return;
        }

        v->clear();
        std::string::size_type i = 0;
        std::string::size_type pos = s.find(delim);
        while (pos != std::string::npos) {
            v->push_back(s.substr(i, pos - i));
            i = ++pos;
            pos = s.find(delim, pos);
        }

        v->push_back(s.substr(i, s.length()));
        return ;
    }

    static void to_lower(const std::string &s, std::string *out) {
        to_lower(s.c_str(), s.length(), out);
    }

    static void to_lower(const char *s, const size_t len, std::string *out) {
        if (!s || len == 0 || !out) {
            return;
        }

        out->clear();
        for (size_t i = 0; i < len; ++i) {
            out->append(1, tolower(*(s + i)));
        }
    }

    static bool is_digits(const std::string &str) {
        return str.find_first_not_of("0123456789") == std::string::npos;
    }

    static bool split_str_and_base64_set(const std::string &s, const char delim, std::unordered_set<std::string> &v) {
        if (s.empty()) {
            return true;
        }

        v.clear();
        std::string::size_type i = 0;
        std::string::size_type pos = s.find(delim);
        while (pos != std::string::npos) {
            std::string base64;
            std::string value = s.substr(i, pos - i);
            if (!Base64Util::encode(value.c_str(), value.length(), &base64)) {
                return false;
            }

            v.insert(base64);
            i = ++pos;
            pos = s.find(delim, pos);
        }

        std::string base64;
        std::string value = s.substr(i, s.length());
        if (!Base64Util::encode(value.c_str(), value.length(), &base64)) {
            return false;
        }
        v.insert(base64);
        return true;
    }

    static void split_str_set(const std::string &s, const char delim, std::unordered_set<std::string> &v) {
        if (s.empty()) {
            return;
        }

        v.clear();
        std::string::size_type i = 0;
        std::string::size_type pos = s.find(delim);
        while (pos != std::string::npos) {
            v.insert(s.substr(i, pos - i));
            i = ++pos;
            pos = s.find(delim, pos);
        }

        v.insert(s.substr(i, s.length()));
        return ;
    }
};

#endif
