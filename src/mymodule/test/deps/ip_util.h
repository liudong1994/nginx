
#ifndef _IP_UTIL_H_
#define _IP_UTIL_H_

#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>

class CIPUtil {
    public:
        CIPUtil() = delete;

    public:
        static bool get_local_ip(std::string *out)
        {
            if (!out) {
                return false;
            }
            const int MAXINTERFACES = 16;
            char *ip = nullptr;
            int fd, intrface;
            struct ifreq buf[MAXINTERFACES];
            struct ifconf ifc;
            if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) {
                ifc.ifc_len = sizeof(buf);
                ifc.ifc_buf = (caddr_t)buf; 
                if (!ioctl(fd, SIOCGIFCONF, (char *)&ifc)) {
                    intrface = ifc.ifc_len / sizeof(struct ifreq);
                    while (intrface-- > 0) {
                        if (!(ioctl (fd, SIOCGIFADDR, (char *) &buf[intrface]))) {
                            ip = (inet_ntoa(((struct sockaddr_in*)
                                            (&buf[intrface].ifr_addr))->sin_addr));
                            break;
                        }
                    }
                }
                close(fd);
            }
 
            if (!ip) {
                return false;
            }
            out->assign(ip);
            return true;
        }
};

#endif /* _IP_UTIL_ */
