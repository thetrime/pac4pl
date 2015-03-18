#include <SWI-Prolog.h>
#include <string.h>
#include <pac.h>
#include <stdio.h>
#ifdef WIN32
#include <windows.h>
#else
#include <sys/socket.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#endif
#if defined(__APPLE__)
#include <SystemConfiguration/SystemConfiguration.h>
#include <CoreFoundation/CoreFoundation.h>
#endif
#if defined(__GCONF__)
#include <gconf/gconf-client.h>
#elif defined (__GIO__)
/* ??? */
#endif



typedef struct
{
   void* lock;
   char* proxy;
} pac_callback_t;
