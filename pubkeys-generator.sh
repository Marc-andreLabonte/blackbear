#!/bin/sh

KEY=`cat id_blackbearkey.pub`

cat << EOF > pubkeys.c
// Auto generated, do not commit to revision control

#include <sys/types.h>  
#include <string.h>

/* NULL pointer is required to be the last element of public keys array. */
char *myownpubkeys[] = {
    "${KEY}",
    NULL
};

int
read_keyfile_mem(char *buf, size_t bufsz, u_long *lineno)
{
    if (myownpubkeys[*lineno] != NULL ){                                                                                                    
        strncpy(buf, myownpubkeys[*lineno], bufsz);
        (*lineno)++;
        return 0;
    } else {
        return -1;
    }

}
EOF
