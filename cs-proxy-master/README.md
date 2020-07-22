# cs-proxy
WARNING: Never pass unsanitized strings to the hostname, port, etc.; they are just passed as-is and might cause shell escape attacks.

Proxy support for C# using OpenBSD nc. nc should be installed or shipped with this (nc is a small executable). stdbuf (GNU coreutils/BSD) or unbuffer from expect (TCL) should preferably be there too (although this can work without it, there might be buffering delays).

WinPTY is recommended for Windows. Can be found at https://github.com/rprichard/winpty .

ProxySocket should be initialized with the values; default uses stdbuf but can be changed later. Comes with utility classes Pair and StatPair, which can be used to pair a Read/Write stream into one large stream.

# Architrcture
GetStream() returns the stream of ProxySocket. ProxySocket should be Start()ed to connect.


# DTLS PSK Client/Server
WARNING: Same.

DTLS wrapper using OpenSSL. Needs openssl in PATH.

# Architecture
Please refer to the Test file.
