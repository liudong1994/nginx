
#ifndef _CONFIG_H_
#define _CONFIG_H_

#include <map>
#include <sstream>
#include <fstream>

#define CONFIG_DELIM '='

class CConfig {
    public:
        CConfig() {}
        virtual ~CConfig() {}

    public:
        std::string log_debug_string() {
            std::stringstream ss;
            for (auto itr = conf.begin(); 
                    itr != conf.end(); ++itr) {
                ss << itr->first << " = " << itr->second << std::endl;
            }

            return ss.str();
        }

        bool parse_from_file(const char *filepath) {
            std::fstream ifs(filepath, std::fstream::in);
            if (!ifs.is_open()) {
                return false;
            }

            std::string line;
            while (getline(ifs, line)) {
                std::string key, val;
                if (parse_to_key_value(line, &key, &val)) {
                    conf.insert(make_pair(key, val));
                }
            }

            return true;
        }

        int64_t get_int64(const std::string & key, const int64_t def = 0) const {
            auto itr = conf.find(key);
            if (itr != conf.end()) {
                return (int64_t)strtoll(itr->second.c_str(), nullptr, 0);
            }

            return def;
        }
        std::string get_string(const std::string & key, const std::string &def = "") const {
            auto itr = conf.find(key);
            if (itr != conf.end()) {
                return itr->second;
            }

            return def;
        }            

        double get_float64(const std::string & key, const double def = 0) const {
            auto itr = conf.find(key);
            if (itr != conf.end()) {
                return strtod(itr->second.c_str(), nullptr);
            }
            return def;
        }

    protected:
        bool parse_to_key_value(const std::string &line,
                std::string *key, std::string *val) {
            size_t pos =  std::string::npos;
            pos = line.find_first_not_of(' ');
            if (pos == std::string::npos ||
                    line[pos] == '#') {
                return false;
            }

            pos = line.find_first_of(CONFIG_DELIM);
            if (pos == std::string::npos || pos == 0) {
                return false;
            }

            const char *s, *e;

            s = line.c_str();
            e = s + pos - 1;
            while (s <= e && *s == ' ') { ++s; }
            while (s <= e && *e == ' ') { --e; }
            if (s > e) {
                return false;
            }
            key->assign(s, e - s + 1);

            s = line.c_str() + pos + 1;
            e = line.c_str() + line.size() - 1;
            while (s <= e && *s == ' ') { ++s; }
            while (s <= e && *e == ' ') { --e; }
            if (s > e) {
                return false;
            }
            val->assign(s, e - s + 1);

            return true;
        }
    private:
        std::map<std::string, std::string> conf;
};

#endif /* _CONFIG_H_ */
