

struct addrinfo *
resolve_host(const char *, int, int, char *, size_t);

int
ssh_connect_reverse(int *, int *, int *, const char *, struct addrinfo *,
    u_short, int, int, int, int);
    

