#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <sys/fcntl.h>
#include "file_util.h"

const char CR = '\n';

using std::string;

int CFileIO::open_file(const std::string & file)
{
    int fd;
    struct stat st;
    fd = open(file.c_str(), O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    if (fstat(fd, &st)) {
        return -1;
    }

    if (st.st_size == 0) { //empty file
        close(fd);
        return 0;
    }

    m_mmptr = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (MAP_FAILED == m_mmptr) {
        return -1;
    }

    m_start = static_cast<char *>(m_mmptr);
    m_offset = m_start;
    m_size = st.st_size;

    return 0;
}

bool CFileIO::get_line(string & line)
{
    if (m_start == nullptr || m_offset == nullptr) {
        return false;
    }

    if (m_offset >= m_start + m_size) {
        return false;
    }

    char * pch = strchr(m_offset, CR);
    if (pch == nullptr) {
        pch = m_start + m_size;
    } 

    line.assign(m_offset, pch - m_offset);
    m_offset = pch + 1;

    return true;
}

int CFileIO::close_file()
{
    if (m_mmptr != MAP_FAILED && m_mmptr != nullptr) {
        m_start = nullptr;
        m_offset = nullptr;
        munmap(m_mmptr, m_size);
        m_mmptr = nullptr;
        m_size = 0;
    }

    return 0;
}
