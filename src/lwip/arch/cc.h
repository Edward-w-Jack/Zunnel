/* lwIP architecture glue for zunnel. The referenced functions are exported
 * from Zig (src/server/netstack.zig). */
#ifndef ZUNNEL_ARCH_CC_H
#define ZUNNEL_ARCH_CC_H

#include <stdlib.h>

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define BYTE_ORDER BIG_ENDIAN
#else
#define BYTE_ORDER LITTLE_ENDIAN
#endif

void zunnel_lwip_assert(const char *msg, int line, const char *file);
unsigned int zunnel_lwip_rand(void);
struct netif;
struct netif *zunnel_route_src(const void *src, const void *dest);

#define LWIP_PLATFORM_DIAG(x)   do { } while (0)
#define LWIP_PLATFORM_ASSERT(x) zunnel_lwip_assert((x), __LINE__, __FILE__)
#define LWIP_RAND()             ((u32_t)zunnel_lwip_rand())

#endif /* ZUNNEL_ARCH_CC_H */
