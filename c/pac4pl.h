#include "../config.h"


#include <SWI-Prolog.h>
#include <string.h>
#include <pac.h>
#include <stdio.h>
#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <dhcpcsdk.h>
#include <iphlpapi.h>
#else
#include <sys/socket.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>

#if defined(__APPLE__) /* Really BSD? */
#include <net/if_dl.h>
#include <SystemConfiguration/SystemConfiguration.h>
#include <CoreFoundation/CoreFoundation.h>
#else    /* Non-BSD */
#define AF_LINK AF_PACKET
#include <sys/ioctl.h>
#endif
#endif
#if defined(HAVE_GCONF)
#include <gconf/gconf-client.h>
#endif
#if defined (HAVE_GSETTINGS)
#include <gio/gio.h>
#endif



typedef struct
{
   void* lock;
   char* proxy;
} pac_callback_t;
