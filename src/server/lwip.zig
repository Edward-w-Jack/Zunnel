pub const c = @cImport({
    @cInclude("lwip/init.h");
    @cInclude("lwip/netif.h");
    @cInclude("lwip/ip4.h");
    @cInclude("lwip/pbuf.h");
    @cInclude("lwip/tcp.h");
    @cInclude("lwip/timeouts.h");
});

pub const ERR_OK: c.err_t = 0;
pub const ERR_MEM: c.err_t = -1;
pub const ERR_ABRT: c.err_t = -13;
