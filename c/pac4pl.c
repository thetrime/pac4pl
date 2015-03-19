#include "pac4pl.h"

#define DEBUG(g, l) (void)0

foreign_t pac_error(char* message)
{
   term_t except;
   if ((except = PL_new_term_ref()) &&      
       PL_unify_term(except,
                     PL_FUNCTOR, PL_new_functor(PL_new_atom("pac_error"), 1),
                     PL_CHARS, message))
      return PL_raise_exception(except);  
   return FALSE;
}

int initialize_callback_lock(void** lock)
{
#ifdef WIN32
   *lock = CreateEvent(NULL, TRUE, FALSE, NULL);
   return (*lock != NULL);
#else
   int* fds;
   *lock = malloc(sizeof(int) * 2);
   fds = (int*)*lock;
   if (!pipe(fds))
      return 0;
#endif
   return 1;
}

int wait_for_lock(void** lock)
{
#ifndef WIN32
   int* fds = (int*)*lock;
   fd_set set;
   struct timeval timeout;
   int rc;
#endif
   
   while(1)
   {
#ifdef WIN32
      DWORD rc = WaitForSingleObject((HANDLE)*lock, 1000);
      if (rc == WAIT_TIMEOUT)
         PL_handle_signals();
      else if (rc == WAIT_OBJECT_0)
         return TRUE;
      else
         return pac_error("Wait failure");
#else
      FD_ZERO(&set);
      FD_SET(fds[0], &set);
      timeout.tv_sec = 1;
      timeout.tv_usec = 0;
      rc = select(fds[0] + 1, &set, NULL, NULL, &timeout);
      if (rc > 0)
         return TRUE;
      else if (rc < 0)
         return pac_error("Wait failure");
#endif
   }
}

void notify_callback(void** lock)
{
#ifdef WIN32
   SetEvent((HANDLE)*lock);
#else
   int* fds = (int*)*lock;
   write(fds[1], "x", 1);
#endif
}

static void notify(void *arg)
{
   pac_callback_t* callback = (pac_callback_t*)arg;
   notify_callback(&callback->lock);
}

static void proxy_found(char *proxy, void *arg)
{
   if (proxy != NULL)
   {
      pac_callback_t* callback = (pac_callback_t*)arg;
      callback->proxy = strdup(proxy);
      free(proxy);
   }
}

foreign_t pl_pac(term_t pacfile, term_t url, term_t host, term_t proxy)
{
   pac_callback_t* callback = NULL;
   char* javascript;
   char* url_text;
   char* host_text;
   struct pac *pac;
   int rc = TRUE;
   size_t len = 0;
   
   if (!PL_get_string_chars(pacfile, &javascript, &len))
      return PL_type_error("atom", pacfile);

   if (!PL_get_atom_chars(url, &url_text))
      return PL_type_error("atom", url);

   if (!PL_get_atom_chars(host, &host_text))
      return PL_type_error("atom", host);
   
   callback = PL_malloc(sizeof(pac_callback_t));
   callback->proxy = NULL;

   initialize_callback_lock(&callback->lock);
   
   pac = pac_init(javascript, 16, notify, callback);
   DEBUG(printf("Searching for proxy: [%s][%s]\n", url_text, host_text), 1);
   pac_find_proxy(pac, url_text, host_text, proxy_found, callback);

   rc = wait_for_lock(&callback->lock);
   if (rc)
      pac_run_callbacks(pac);   
   if (rc && callback->proxy != NULL)
   {
      rc = PL_unify_atom_chars(proxy, callback->proxy);
   }
   else
      rc = FALSE;
   PL_free(callback);
   return rc;
}

#if defined(WIN32)
static int dhcp_initialized = 0;
#elif defined(HAVE_GIO)
GSettings* gio_client = NULL;
#elif defined(HAVE_GCONF)
GConfClient* gconf_client = NULL;
#endif
#define WORKING_BUFFER_SIZE 15000


#ifdef WIN32
const char* inet_ntop(int af, const void* src, char* dst, int cnt)
{ 
   struct sockaddr_in srcaddr;   
   memset(&srcaddr, 0, sizeof(struct sockaddr_in));
   memcpy(&(srcaddr.sin_addr), src, sizeof(srcaddr.sin_addr));   
   srcaddr.sin_family = af;
   if (WSAAddressToString((struct sockaddr*) &srcaddr, sizeof(struct sockaddr_in), 0, dst, (LPDWORD) &cnt) != 0)
      return NULL;
   return dst;
}
#endif

foreign_t system_wpad_url(term_t wpad_url)
{
#ifdef WIN64     /* The 32-bit version of MingW is so badly broken that I just gave up.
                    It is missing inet_ntop and DhcpRequestParams in the libraries, which are
                    fairly fundemantal. mingw-w64 is OK though
                 */
   DWORD result;
   BYTE buffer[1000];
   DWORD size = sizeof(buffer);
   DHCPCAPI_PARAMS option = { 0, 252, FALSE, 0, 0 };
   DHCPCAPI_PARAMS_ARRAY requestParams = { 1, &option };
   DHCPCAPI_PARAMS_ARRAY sendParams = { 0, NULL };
   ULONG adapters_size = WORKING_BUFFER_SIZE;
   PIP_ADAPTER_ADDRESSES adapters = NULL;
   IP_ADAPTER_ADDRESSES* adapter = NULL;

   
   if (!dhcp_initialized)
   {
      /* We cannot use DHCP if the library would not initialize. Fail over to DNS */
      PL_fail;
   }
   /* We need to know the adapter 'name' in Windows to query the DHCP service */   
   do
   {
      if ((adapters = PL_malloc(adapters_size)) == NULL)
         return FALSE;   
      
      result = GetAdaptersAddresses(AF_UNSPEC,
                                    GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_FRIENDLY_NAME,
                                    NULL,
                                    adapters,
                                    &adapters_size);
      
      if (result == ERROR_BUFFER_OVERFLOW)
      {
         PL_free(adapters);         
      }
   } while (result == ERROR_BUFFER_OVERFLOW);
   
   if (result == ERROR_NO_DATA) /* No network adapters installed? */
   {
      PL_free(adapters);
      PL_fail;
   }

   if (result != ERROR_SUCCESS) /* Fail over to DNS */
   {
      PL_free(adapters);
      PL_fail;
   }

   for (adapter = adapters; adapter; adapter = adapter->Next)
   {
      WCHAR* adapter_name;
      size_t adapter_name_len;
      /* Try this adapter */
      if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK) /* Unless it is a loopback */
         continue;
      if ((adapter->Flags & IP_ADAPTER_DHCP_ENABLED) == 0) /* Or it does not have DHCP enabled */
         continue;
      /* Most systems will have at most one such adapter. This implementation will stop on the first one that reports WPAD */
      adapter_name_len = MultiByteToWideChar(0, 0, adapter->AdapterName, -1, adapter_name, 0);
      adapter_name = PL_malloc(adapter_name_len);
      MultiByteToWideChar(0, 0, adapter->AdapterName, -1, adapter_name, adapter_name_len);
      result = DhcpRequestParams(DHCPCAPI_REQUEST_SYNCHRONOUS, NULL, adapter_name, NULL, sendParams, requestParams, buffer, &size, NULL);
      PL_free(adapter_name);
      if (result != ERROR_SUCCESS)  /* Keep looking? */
         continue;
      /* We have a result! */
      PL_free(adapters);      
      return PL_unify_atom_chars(wpad_url, option.Data);
   }
   /* None of the adapters had a DHCP lease from a server that has the WPAD URL */
   PL_free(adapters);
   PL_fail;
#elif defined(__APPLE__)
   int rc = 0;
   CFDictionaryRef config = SCDynamicStoreCopyProxies(NULL);
   if (config)
   {
      CFStringRef pac_url_ref = NULL;
      if ((pac_url_ref = CFDictionaryGetValue(config, kSCPropNetProxiesProxyAutoConfigURLString)) != NULL)
      {
         char url[257]; // Maximum length is 256
         CFStringGetCString(pac_url_ref, url, sizeof(url), kCFStringEncodingASCII);
         rc = PL_unify_atom_chars(wpad_url, url);
      }
   }
   CFRelease(config);
   return rc;
#elif defined(HAVE_GCONF)
   int rc = 0;
   GError* error;
   if (gconf_client)
   {
      const char* key = "/system/proxy/autoconfig_url";
      gchar* value = gconf_client_get_string(gconf_client, key, &error);
      if (HandleGError(error, key))
         PL_fail;
      if (value)
      {
         rc = PL_unify_atom_chars(wpad_url, value);
         g_free(value);
      }
   }
   return rc;
#elif defined(HAVE_GIO)
   int rc = 0;
   gchar* value = g_settings_get_string(gio_client, "autoconfig-url");
   if (value)
   {
      rc = PL_unify_atom_chars(wpad_url, value);
      g_free(value);
   }
   return rc;
#else
   PL_fail;
#endif
}

foreign_t enumerate_network_interfaces(term_t iflist)
{
   term_t head = PL_copy_term_ref(iflist);
   term_t item = PL_new_term_ref();
   functor_t mac6 = PL_new_functor(PL_new_atom("mac"), 6);
   functor_t iface3 = PL_new_functor(PL_new_atom("interface"), 3);
   functor_t ip4 = PL_new_functor(PL_new_atom("ip"), 4);
#ifdef WIN32
   PIP_ADAPTER_INFO info;
   PIP_ADAPTER_INFO p = NULL;
   ULONG buflen = sizeof(IP_ADAPTER_INFO);
   
   /* This is a bit weird. We must allocate a large enough buffer, so we call twice to find out the right size */
   info = PL_malloc(buflen);
   if (!info)
      return FALSE;
   if (GetAdaptersInfo(info, &buflen) == ERROR_BUFFER_OVERFLOW)
   {
      /* Out of memory? */
      PL_free(info);
      PL_fail;
   }
   PL_free(info);
   info = PL_malloc(buflen);
   if (!info)
      return FALSE;   
   if (GetAdaptersInfo(info, &buflen) != ERROR_SUCCESS)
   {
      PL_free(info);
      PL_fail;
   }
   /* OK, at this point we have the info we need */
   p = info;
   while (p != NULL)
   {
      // Name is p->AdapterName 
      if (p->Type == MIB_IF_TYPE_ETHERNET)
      {
         PIP_ADDR_STRING ipaddr;
         if (!PL_unify_list(head, item, head))
            break;
         if (!PL_unify_term(item,
                            PL_FUNCTOR, iface3,
                            PL_CHARS, p->AdapterName,
                            PL_CHARS, "dl",
                            PL_FUNCTOR, mac6,
                            PL_INT, p->Address[0] & 0xff,
                            PL_INT, p->Address[1] & 0xff,
                            PL_INT, p->Address[2] & 0xff,
                            PL_INT, p->Address[3] & 0xff,
                            PL_INT, p->Address[4] & 0xff,
                            PL_INT, p->Address[5] & 0xff,
                            PL_INT, p->Address[6] & 0xff))
            break;
         ipaddr = &p->IpAddressList;
         while (ipaddr != NULL)
         {
            int ip[4];
            char* ipstring = ipaddr->IpAddress.String;
            if (sscanf(ipstring, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3]) != 4)
               break;
            if (!PL_unify_list(head, item, head))
               break;
            if (!PL_unify_term(item,
                               PL_FUNCTOR, iface3,
                               PL_CHARS, p->AdapterName,
                               PL_CHARS, "ip",
                               PL_FUNCTOR, ip4,
                               PL_INT, ip[0] & 0xff,
                               PL_INT, ip[1] & 0xff,
                               PL_INT, ip[2] & 0xff,
                               PL_INT, ip[3] & 0xff))
            break;
            ipaddr = ipaddr->Next;            
         }
         p = p->Next;
      }
   }
   PL_free(info);
#else /* Unix */
   struct ifaddrs* ifaddr;
   struct ifaddrs* p;

   if (getifaddrs(&ifaddr) != 0)
      return FALSE;
   p = ifaddr;
   while(p != NULL)
   {
      if (p->ifa_addr != NULL &&
          (p->ifa_flags & IFF_UP) &&
          !(p->ifa_flags & IFF_LOOPBACK) &&
          !(p->ifa_flags & IFF_NOARP) &&
          !(p->ifa_flags & IFF_POINTOPOINT))
      {
         if (p->ifa_addr->sa_family == AF_LINK)
         {
            struct sockaddr_dl* addr = (struct sockaddr_dl*)p->ifa_addr;
#ifdef __linux__
            struct ifreq ifr;
            int fd = socket(AF_INET, SOCK_DGRAM, 0);
            ifr.ifr_addr.sa_family = AF_INET;
            strcpy(ifr.ifr_name, p->ifa_name);
            ioctl(fd, SIOCGIFHWADDR, &ifr);
            close(fd);
            char* link = ifr.ifr_hwaddr.sa_data;
#else
            char* link = LLADDR(addr);
#endif
            if (!PL_unify_list(head, item, head))
               break;
            if (!PL_unify_term(item,
                               PL_FUNCTOR, iface3,
                               PL_CHARS, p->ifa_name,
                               PL_CHARS, "dl",
                               PL_FUNCTOR, mac6,
                               PL_INT, link[0] & 0xff,
                               PL_INT, link[1] & 0xff,
                               PL_INT, link[2] & 0xff,
                               PL_INT, link[3] & 0xff,
                               PL_INT, link[4] & 0xff,
                               PL_INT, link[5] & 0xff,
                               PL_INT, link[6] & 0xff))
               break;
         }
         else if (p->ifa_addr->sa_family == AF_INET)
         {
            struct sockaddr_in* addr = (struct sockaddr_in*)p->ifa_addr;
            in_addr_t ip = ntohl(addr->sin_addr.s_addr);
            if (!PL_unify_list(head, item, head))
               break;
            if (!PL_unify_term(item,
                               PL_FUNCTOR, iface3,
                               PL_CHARS, p->ifa_name,
                               PL_CHARS, "ip",
                               PL_FUNCTOR, ip4,
                               PL_INT, (ip >> 24) & 0xff,
                               PL_INT, (ip >> 16) & 0xff,
                               PL_INT, (ip >> 8) & 0xff,
                               PL_INT, (ip >> 0) & 0xff))
               break;
         }
      }
      p = p->ifa_next;
   }
   freeifaddrs(ifaddr);
#endif
   return PL_unify_nil(head);   
}

install_t install()
{
#ifdef WIN32
   DWORD result;
   DWORD version;
   result = DhcpCApiInitialize(&version);
   if (result == 0)
      dhcp_initialized = 1;
#elif defined(HAVE_GCONF)
   gconf_client = gconf_client_get_default();
#elif defined(HAVE_GIO)
   gio_client = g_settings_new("org.gnome.system.proxy");
#endif      
   PL_register_foreign("c_pac", 4, pl_pac, 0);
   PL_register_foreign("system_wpad_url", 1, system_wpad_url, 0);
   PL_register_foreign("enumerate_network_interfaces", 1, enumerate_network_interfaces, 0);
}
