#ifndef FILE_UTIL_H_
#define FILE_UTIL_H_

#include <string>

class CFileIO {
    public:
        CFileIO():
            m_mmptr(nullptr),
            m_start(nullptr),
            m_offset(nullptr),
            m_size(0)
        {}
        virtual ~CFileIO() {
            close_file();
        }

    public:
        int open_file(const std::string & file);
        bool get_line(std::string & line);
        bool is_open() 
        {
            if (m_mmptr == nullptr || m_start == nullptr || m_offset == nullptr) {
                return false;
            }

            return true;
        }
        size_t get_size() 
        {
            return m_size;
        }
        int close_file();

    private:
        void * m_mmptr;   //mmap ptr
        char * m_start;   //start
        char * m_offset;  //curr offset
        size_t m_size;
};

#endif //FILE_UTIL_H_
