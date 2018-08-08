
#ifndef TIME_UTIL_H_
#define TIME_UTIL_H_

#include <string.h>
#include <time.h>

class CClockTime
{
    public:
       CClockTime():
           m_total_time(0),
           is_runing(false) 
       {} 
       virtual ~CClockTime() {}

    public:
        inline void start() 
        {
            m_total_time = 0;
            is_runing = true;
            clock_gettime(CLOCK_MONOTONIC, &m_start);
        }
        inline void resume()
        {
            is_runing = true;
            clock_gettime(CLOCK_MONOTONIC, &m_start);
        }

        inline uint64_t stop()
        {
            if (!is_runing) {
                return m_total_time;
            }

            clock_gettime(CLOCK_MONOTONIC, &m_stop);
            m_total_time +=  diff(m_stop, m_start); //accumulation
            is_runing = false;

            return m_total_time;
        }

        inline uint64_t get_time()
        {
            if (!is_runing) {
                return m_total_time;
            }

            struct timespec tmp_time;
            clock_gettime(CLOCK_MONOTONIC, &tmp_time);
            return diff(tmp_time, m_start) + m_total_time;
        }

    protected:
        inline uint64_t diff(struct timespec & a, struct timespec & b)
        {
            return (uint64_t)((a.tv_sec - b.tv_sec) * 1000000 + (a.tv_nsec - b.tv_nsec) / 1000);
        }

    private:
        struct timespec m_start;
        struct timespec m_stop;
        uint64_t m_total_time; //us
        bool is_runing;
};

class CTimeUtil
{
    public:
        CTimeUtil() {}
        virtual ~CTimeUtil() {}

    public:
        static void get_date(std::string & date) {
            tm stm;
            time_t t= time(NULL);  
            localtime_r(&t, &stm);
            char buff[32] = {0};      
            snprintf(buff, sizeof(buff), "%04d%02d%02d", stm.tm_year + 1900, stm.tm_mon + 1, stm.tm_mday);
            date.assign(buff);
        }

        static void get_timestamp(time_t *t = NULL, uint64_t *t_ms = NULL) {
            struct timespec tmp_time;
            clock_gettime(CLOCK_REALTIME, &tmp_time);
            if (t) {
                *t = (time_t)tmp_time.tv_sec;
            }
            if (t_ms) {
                *t_ms = (uint64_t)(tmp_time.tv_sec * 1000 + tmp_time.tv_nsec / 1000000);
            }
        }

        static void get_fmt_time(const time_t t, std::string *out) {
            struct tm stm;
            localtime_r(&t, &stm);
            char buff[64];
            snprintf(buff, sizeof(buff), "%04d-%02d-%02d %02d:%02d:%02d",
                    stm.tm_year + 1900, stm.tm_mon + 1, stm.tm_mday,
                    stm.tm_hour, stm.tm_min, stm.tm_sec);

            out->assign(buff);
        }

        static void get_hour(const time_t t, std::string *out) {
            struct tm stm;
            localtime_r(&t, &stm);
            char buff[64];
            snprintf(buff, sizeof(buff), "%02d", stm.tm_hour);

            out->assign(buff);
        }
};

#endif //TIME_UTIL_H_
