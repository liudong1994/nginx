#ifndef __UTILS_H__
#define __UTILS_H__

#include <string>
#include <map>
#include <assert.h>


// Uri
std::string uri_decode(const std::string &uri);
std::string uri_encode(const std::string &uri);

// string
void split_string(std::map<std::string, std::string> &kv, const char *s, size_t len, char delimiter);


#endif

