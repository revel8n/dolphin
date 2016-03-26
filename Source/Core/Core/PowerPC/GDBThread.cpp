// Copyright 2016 Dolphin Emulator Project
// Licensed under GPLv2+
// Refer to the license.txt file included.

#include "Core/PowerPC/GDBThread.h"

#include "Common/ChunkFile.h"
#include "Common/CommonFuncs.h"
#include "Common/CommonTypes.h"
#include "Common/StringUtil.h"
#include "Common/Thread.h"
#include "Common/Logging/Log.h"
#include "Core/ConfigManager.h"
#include "Core/Core.h"
#include "Core/HW/CPU.h"
#include "Core/PowerPC/PowerPC.h"
#include "Core/PowerPC/Interpreter/Interpreter_FPUtils.h"

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
//#include <unistd.h>
#ifdef _WIN32
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <iphlpapi.h>
#else
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif
#include <stdarg.h>

#define fail(msg)   \
{                   \
    DEBUG_LOG(GDB_THREAD, msg); \
    gdb_deinit();   \
    return;         \
}

#define failr(msg)  \
{                   \
    DEBUG_LOG(GDB_THREAD, msg); \
    gdb_deinit();   \
    return 0;       \
}

#define		GDB_MAX_BP	100

#define		GDB_STUB_START	'$'
#define		GDB_STUB_END	'#'
#define		GDB_STUB_ACK	'+'
#define		GDB_STUB_NAK	'-'

#ifdef _WIN32
#define SIGTRAP 5
#define	SIGTERM 15
#define SIGSTOP 23 // values listed for MIPS?
#define SIGCONT 25 // values listed for MIPS?
#ifndef MSG_WAITALL
#define MSG_WAITALL  8
#endif
#endif

#define REGISTER_ID(category, index) ((category << 8) | index)

enum gdb_bp_type
{
    GDB_BP_TYPE_NONE = 0,
    GDB_BP_TYPE_X,
    GDB_BP_TYPE_R,
    GDB_BP_TYPE_W,
    GDB_BP_TYPE_A,
};

// --------------------------------------------------------------------------------------
//  GDBThread Implementations
// --------------------------------------------------------------------------------------
GDBThread::GDBThread() 
{
}

GDBThread::~GDBThread()
{
    Terminate();
}

bool GDBThread::Initialize()
{
    NOTICE_LOG(GDB_THREAD, "GDB thread: Initialize");

    const SConfig& _CoreParameter = SConfig::GetInstance();

    if (_CoreParameter.iGDBPort <= 0)
        return false;

    server_thread = std::thread(std::mem_fun(&GDBThread::ExecuteTaskInThread), this);

    return true;
}

void GDBThread::Terminate()
{
    NOTICE_LOG(GDB_THREAD, "GDB thread: Terminate");

    OnStop();

    if (server_thread.joinable())
        server_thread.join();
}

void GDBThread::OnStart()
{
    NOTICE_LOG(GDB_THREAD, "GDB thread: On Start");

    Common::SetCurrentThreadName("GDBThread");
}

void GDBThread::OnStop()
{
    NOTICE_LOG(GDB_THREAD, "GDB thread: On Stop");

    is_running = false;

    gdb_interface.gdb_signal(SIGTERM);
    gdb_interface.gdb_deinit();
}

void GDBThread::OnPause()
{
    u64 addr;
    MemCheckCondition cond;

    NOTICE_LOG(GDB_THREAD, "GDB thread: On Pause");

    if (PowerPC::CPU_POWERDOWN == PowerPC::GetState())
    {
        gdb_interface.gdb_signal(SIGTERM);
        gdb_interface.gdb_deinit();
    }
    else if (PowerPC::breakpoints.GetBreakpointTriggered(addr, cond))
    {
        gdb_interface.gdb_signal(SIGTRAP, addr, cond);
    }
    else
    {
        gdb_interface.gdb_signal(SIGSTOP);
    }
}
void GDBThread::OnResume()
{
    NOTICE_LOG(GDB_THREAD, "GDB thread: On Resume");

    if (PowerPC::CPU_POWERDOWN == PowerPC::GetState())
    {
        gdb_interface.gdb_signal(SIGTERM);
        gdb_interface.gdb_deinit();
    }
    else
    {
        gdb_interface.gdb_signal(SIGCONT);
    }
}

void GDBThread::ExecuteTaskInThread()
{
    OnStart();

    NOTICE_LOG(GDB_THREAD, "Starting GDB stub thread.");

    is_running = true;

    const SConfig& _CoreParameter = SConfig::GetInstance();

    while (is_running)
    {
        if (PowerPC::CPU_POWERDOWN != PowerPC::GetState())
        {
#ifndef _WIN32
            if (!_CoreParameter.gdb_socket.empty())
            {
                gdb_interface.gdb_init_local(_CoreParameter.gdb_socket.data());
            }
            else
#endif
            if (_CoreParameter.iGDBPort > 0)
            {
                gdb_interface.gdb_init((u32)_CoreParameter.iGDBPort);
                // break at next instruction (the first instruction)
            }

            // abuse abort signal for attach
            gdb_interface.gdb_signal(SIGABRT);

            CPU::EnableStepping(true);

            PowerPC::CPUState previous_state = PowerPC::GetState();

            while (is_running && (0 <= gdb_interface.gdb_data_available()))
            {
                gdb_interface.gdb_handle_events();

                const PowerPC::CPUState current_state = PowerPC::GetState();
                if (current_state != previous_state)
                {
                    switch (current_state)
                    {
                    case PowerPC::CPU_RUNNING:
                        OnResume();
                        break;
                    case PowerPC::CPU_STEPPING:
                        OnPause();
                        break;
                    case PowerPC::CPU_POWERDOWN:
                        OnStop();
                        break;
                    default:
                        break;
                    }
                }

                previous_state = current_state;

                Common::YieldCPU();
            }

            gdb_interface.gdb_deinit();
        }

        Common::YieldCPU();
    }

    NOTICE_LOG(GDB_THREAD, "Terminating GDB stub thread.");
}


// private helpers
static u8 hex2char(u8 hex)
{
    if (hex >= '0' && hex <= '9')
        return hex - '0';
    else if (hex >= 'a' && hex <= 'f')
        return hex - 'a' + 0xa;
    else if (hex >= 'A' && hex <= 'F')
        return hex - 'A' + 0xa;

    DEBUG_LOG(GDB_THREAD, "Invalid nibble: %c (%02x)\n", hex, hex);
    return 0;
}

static u8 nibble2hex(u8 n)
{
    n &= 0xf;
    if (n < 0xa)
        return '0' + n;
    else
        return 'A' + n - 0xa;
}

static void mem2hex(u8 *dst, u32 src, u32 len)
{
    u8 tmp;

    while (len-- > 0)
    {
        tmp = PowerPC::HostRead_U8(src++);

        *dst++ = nibble2hex(tmp >> 4);
        *dst++ = nibble2hex(tmp);
    }
}

static void hex2mem(u32 dst, u8 *src, u32 len)
{
    u8 tmp;

    while (len-- > 0)
    {
        tmp = hex2char(*src++) << 4;
        tmp |= hex2char(*src++);

        PowerPC::HostWrite_U8(tmp, dst++);
    }
}

static void wbe32hex(u8 *p, u32 v)
{
    u32 i;

    for (i = 0; i < 8; i++)
        p[i] = nibble2hex(u8(v >> (28 - 4 * i)));
}

static void wbe64hex(u8 *p, u64 v)
{
    u32 i;
    for (i = 0; i < 16; i++)
        p[i] = nibble2hex(u8(v >> (60 - 4 * i)));
}

static void wle32hex(u8 *p, u32 v)
{
    u32 i;

    for (i = 0; i < 8; i++)
        p[i] = nibble2hex(u8(v >> (4 * (i ^ 1))));
}

static void wle64hex(u8 *p, u64 v)
{
    u32 i;

    for (i = 0; i < 16; i++)
        p[i] = nibble2hex(u8(v >> (4 * (i ^ 1))));
}

static u32 rbe32hex(u8 *p)
{
    u32 i;
    u32 res = 0;

    for (i = 0; i < 8; i++)
        res = (res << 4) | hex2char(p[i]);

    return res;
}

static u64 rbe64hex(u8 *p)
{
    u32 i;
    u64 res = 0;

    for (i = 0; i < 16; i++)
        res = (res << 4) | hex2char(p[i]);

    return res;
}

static u32 rle32hex(u8 *p)
{
    u32 i;
    u32 res = 0;

    for (i = 0; i < 8; i++)
        res = (res) | (hex2char(p[i]) << (4 * (i ^ 1)));

    return res;
}

static u32 rle64hex(u8 *p)
{
    u32 i;
    u32 res = 0;

    for (i = 0; i < 16; i++)
        res = (res) | (hex2char(p[i]) << (4 * (i ^ 1)));

    return res;
}

// GDB stub interface
gdb_stub::gdb_stub() :
sock(-1),
sig(0),
connected(false)
{
}
gdb_stub::~gdb_stub()
{
    gdb_deinit();
}

#ifndef _WIN32
void gdb_stub::gdb_init_local(const char *socket)
{
    unlink(socket);

    sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, socket);

    gdb_init_generic(PF_LOCAL, (const sockaddr *)&addr, sizeof(addr),
        NULL, NULL);
}
#endif

void gdb_stub::gdb_init(u32 port)
{
    sockaddr_in saddr_server = {};
    sockaddr_in saddr_client;

    saddr_server.sin_family = AF_INET;
    saddr_server.sin_port = htons(port);
    saddr_server.sin_addr.s_addr = INADDR_ANY;

    socklen_t client_addrlen = sizeof(saddr_client);

    gdb_init_generic(PF_INET,
        (const sockaddr *)&saddr_server, sizeof(saddr_server),
        (sockaddr *)&saddr_client, &client_addrlen);

    saddr_client.sin_addr.s_addr = ntohl(saddr_client.sin_addr.s_addr);
    /*if (((saddr_client.sin_addr.s_addr >> 24) & 0xff) != 127 ||
    *      ((saddr_client.sin_addr.s_addr >> 16) & 0xff) !=   0 ||
    *      ((saddr_client.sin_addr.s_addr >>  8) & 0xff) !=   0 ||
    *      ((saddr_client.sin_addr.s_addr >>  0) & 0xff) !=   1)
    *      ERROR_LOG(GDB_THREAD, "gdb: incoming connection not from localhost");
    */
}

void gdb_stub::gdb_init_generic(int domain,
    const sockaddr *server_addr, socklen_t server_addrlen,
    sockaddr *client_addr, socklen_t *client_addrlen)
{
    int on;
#ifdef _WIN32
    WSADATA init_data;
    WSAStartup(MAKEWORD(2, 2), &init_data);
#endif

    tmpsock = (int)socket(domain, SOCK_STREAM, 0);
    if (tmpsock == -1)
        ERROR_LOG(GDB_THREAD, "Failed to create gdb socket");

    on = 1;
    if (setsockopt(tmpsock, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof on) < 0)
        ERROR_LOG(GDB_THREAD, "Failed to setsockopt");

    if (bind(tmpsock, server_addr, server_addrlen) < 0)
        ERROR_LOG(GDB_THREAD, "Failed to bind gdb socket");

    if (listen(tmpsock, 1) < 0)
        ERROR_LOG(GDB_THREAD, "Failed to listen to gdb socket");

    INFO_LOG(GDB_THREAD, "Waiting for gdb to connect...\n");

    sock = (int)accept(tmpsock, client_addr, client_addrlen);
    if (sock < 0)
        ERROR_LOG(GDB_THREAD, "Failed to accept gdb client");
    INFO_LOG(GDB_THREAD, "Client connected.\n");

    closesocket(tmpsock);
    tmpsock = -1;
}

void gdb_stub::gdb_deinit()
{
    if (tmpsock != -1)
    {
        shutdown(tmpsock, SD_BOTH);
        closesocket(tmpsock);
        tmpsock = -1;
    }
    if (sock != -1)
    {
        shutdown(sock, SD_BOTH);
        closesocket(sock);
        sock = -1;
    }

    connected = false;

#ifdef _WIN32
    WSACleanup();
#endif
}

int gdb_stub::gdb_data_available()
{
    struct timeval t;
    fd_set _fds, *fds = &_fds;

    FD_ZERO(fds);
    FD_SET(sock, fds);

    t.tv_sec = 0;
    t.tv_usec = 20;

    if (select(sock + 1, fds, NULL, NULL, &t) < 0)
        return -1;

    if (FD_ISSET(sock, fds))
        return 1;
    return 0;
}

void gdb_stub::gdb_handle_events()
{
    if (!connected)
        return;

    while (0 < gdb_data_available())
    {
        gdb_read_command();
        gdb_parse_command();
    }
}

void gdb_stub::gdb_read_command(void)
{
    u8 c;
    u8 chk_read, chk_calc;

    cmd_len = 0;
    memset(cmd_bfr, 0, sizeof cmd_bfr);

    c = gdb_read_byte();
    if (c != GDB_STUB_START)
    {
        DEBUG_LOG(GDB_THREAD, "gdb: read invalid byte %02x\n", c);
        return;
    }

    while ((c = gdb_read_byte()) != GDB_STUB_END)
    {
        cmd_bfr[cmd_len++] = c;
        if (cmd_len == sizeof cmd_bfr)
            fail("gdb: cmd_bfr overflow\n");
    }

    chk_read = hex2char(gdb_read_byte()) << 4;
    chk_read |= hex2char(gdb_read_byte());

    chk_calc = gdb_calc_chksum();

    if (chk_calc != chk_read)
    {
        DEBUG_LOG(GDB_THREAD, "gdb: invalid checksum: calculated %02x and read %02x for $%s# (length: %d)\n", chk_calc, chk_read, cmd_bfr, cmd_len);
        cmd_len = 0;

        gdb_nak();
    }

    DEBUG_LOG(GDB_THREAD, "gdb: read command %c with a length of %d: %s\n", cmd_bfr[0], cmd_len, cmd_bfr);
}

void gdb_stub::gdb_parse_command(void)
{
    if (cmd_len == 0)
        return;

    switch (cmd_bfr[0])
    {
    case 'q':
        gdb_handle_query();
        break;
    case 'H':
        gdb_handle_set_thread();
        break;
    case '?':
        gdb_handle_signal();
        break;
    case 'D':
        gdb_detach();
        break;
    case 'k':
        gdb_kill();
        break;
    case 'g':
        gdb_read_registers();
        break;
    case 'G':
        gdb_write_registers();
        break;
    case 'p':
        gdb_read_register();
        break;
    case 'P':
        gdb_write_register();
        break;
    case 'm':
        gdb_read_mem();
        break;
    case 'M':
        gdb_write_mem();
        break;
    case 'c':
        gdb_continue();
        break;
    case 's':
        gdb_step();
        break;
    case ' ':
        gdb_pause();
        break;
    case 'z':
        gdb_remove_bp();
        break;
    case 'Z':
        gdb_add_bp();
        break;
    default:
        gdb_ack();
        gdb_reply("");
        break;
    }
}

u8 gdb_stub::gdb_read_byte(void)
{
    if (!connected)
        return 0;

    size_t res;
    u8 c;

    res = recv(sock, (char*)&c, 1, MSG_WAITALL);
    if (res != 1)
        failr("recv failed");

    return c;
}

u8 gdb_stub::gdb_calc_chksum(void)
{
    u32 len = cmd_len;
    u8 *ptr = cmd_bfr;
    u8 c = 0;

    while (len-- > 0)
        c += *ptr++;

    return c;
}

void gdb_stub::gdb_reply(const char *reply)
{
    if (!connected)
        return;

    u8 chk;
    u32 left;
    u8 *ptr;
    int n;

    memset(cmd_bfr, 0, sizeof cmd_bfr);

    cmd_len = (u32)strlen(reply);
    if (cmd_len + 4 > sizeof cmd_bfr)
        fail("cmd_bfr overflow in gdb_reply");

    memcpy(cmd_bfr + 1, reply, cmd_len);

    cmd_len++;
    chk = gdb_calc_chksum();
    cmd_len--;
    cmd_bfr[0] = GDB_STUB_START;
    cmd_bfr[cmd_len + 1] = GDB_STUB_END;
    cmd_bfr[cmd_len + 2] = nibble2hex(chk >> 4);
    cmd_bfr[cmd_len + 3] = nibble2hex(chk);

    //DEBUG_LOG(GDB_THREAD, "gdb: reply (len: %d): %s\n", cmd_len, cmd_bfr);

    ptr = cmd_bfr;
    left = cmd_len + 4;
    while (left > 0)
    {
        n = send(sock, (const char*)ptr, left, 0);
        if (n < 0)
            fail("gdb: send failed");
        left -= n;
        ptr += n;
    }
}

void gdb_stub::gdb_nak(void)
{
    if (!connected)
        return;

    const char nak = GDB_STUB_NAK;
    size_t res;

    res = send(sock, &nak, 1, 0);
    if (res != 1)
        fail("send failed");
}

void gdb_stub::gdb_ack(void)
{
    if (!connected)
        return;

    const char ack = GDB_STUB_ACK;
    size_t res;

    res = send(sock, &ack, 1, 0);
    if (res != 1)
        fail("send failed");
}

void gdb_stub::gdb_handle_signal(void)
{
    if (!connected)
        return;

    char bfr[128] = { 0 };

    gdb_ack();

    memset(bfr, 0, sizeof bfr);
    switch (signal_cond)
    {
    case MEMCHECK_NONE:
        sprintf(bfr, "T%02X%08X:%08X", sig, 64, PC);
        break;
    case MEMCHECK_READ:
        sprintf(bfr, "T%02X%08X:%08X;rwatch:%08llX", sig, 64, PC, signal_addr);
        break;
    case MEMCHECK_WRITE:
        sprintf(bfr, "T%02X%08X:%08X;watch:%08llX", sig, 64, PC, signal_addr);
        break;
    case MEMCHECK_READWRITE:
        sprintf(bfr, "T%02X%08X:%08X;awatch:%08llX", sig, 64, PC, signal_addr);
        break;
    default:
        return;
        break;
    }

    gdb_reply(bfr);
}

void gdb_stub::gdb_continue(void)
{
    if (!connected)
        return;

    gdb_ack();

    if (PowerPC::CPU_STEPPING == PowerPC::GetState())
    {
        CPU::EnableStepping(false);
    }
}

void gdb_stub::gdb_detach(void)
{
    if (!connected)
        return;

    gdb_ack();
    gdb_reply("OK");
    gdb_deinit();
}

void gdb_stub::gdb_read_registers(void)
{
    if (!connected)
        return;

    u8 bfr[GDB_BFR_MAX - 4] = { 0 };

    gdb_ack();

    u8* bufptr = bfr;

    for (u32 id = 0; id <= 71; ++id)
    {
        if (0 <= id && id <= 31)
        {
            wbe32hex(bufptr, GPR(id));
            bufptr += 8;
        }
        else if (32 <= id && id <= 63)
        {
            wbe64hex(bufptr, riPS1(id - 32));
            bufptr += 16;
            wbe64hex(bufptr, riPS0(id - 32));
            bufptr += 16;
        }
        else
        {
            switch (id)
            {
            case 64:
                wbe32hex(bufptr, PC);
                bufptr += 8;
                break;
            case 65:
                wbe32hex(bufptr, MSR);
                bufptr += 8;
                break;
            case 66:
                wbe32hex(bufptr, GetCR());
                bufptr += 8;
                break;
            case 67:
                wbe32hex(bufptr, LR);
                bufptr += 8;
                break;
            case 68:
                wbe32hex(bufptr, CTR);
                bufptr += 8;
                break;
            case 69:
                wbe32hex(bufptr, XER);
                bufptr += 8;
                break;
            case 70:
                wbe32hex(bufptr, 0x0BADC0DE);
                bufptr += 8;
                break;
            case 71:
                wbe32hex(bufptr, FPSCR.Hex);
                bufptr += 8;
                break;
            }
        }
    }

    gdb_reply((char *)bfr);
}

void gdb_stub::gdb_write_registers(void)
{
    if (!connected)
        return;

    gdb_ack();

    u8* bufptr = cmd_bfr + 1;

    for (u32 id = 0; id <= 71; ++id)
    {
        if (0 <= id && id <= 31)
        {
            GPR(id) = rbe32hex(bufptr);
            bufptr += 8;
        }
        else if (32 <= id && id <= 63)
        {
            riPS1(id - 32) = rbe64hex(bufptr);
            bufptr += 16;
            riPS0(id - 32) = rbe64hex(bufptr + 16);
            bufptr += 16;
        }
        else
        {
            switch (id)
            {
            case 64:
                PC = rbe32hex(bufptr);
                bufptr += 8;
                break;
            case 65:
                MSR = rbe32hex(bufptr);
                bufptr += 8;
                break;
            case 66:
                SetCR(rbe32hex(bufptr));
                bufptr += 8;
                break;
            case 67:
                LR = rbe32hex(bufptr);
                bufptr += 8;
                break;
            case 68:
                CTR = rbe32hex(bufptr);
                bufptr += 8;
                break;
            case 69:
                XER = rbe32hex(bufptr);
                bufptr += 8;
                break;
            case 70:
                // do nothing, we don't have MQ
                bufptr += 8;
                break;
            case 71:
                FPSCR.Hex = rbe32hex(bufptr);
                bufptr += 8;
                break;
            }
        }
    }

    gdb_reply("OK");
}

void gdb_stub::gdb_handle_set_thread(void)
{
    if (!connected)
        return;

    gdb_ack();
    if (memcmp(cmd_bfr, "Hg0", 3) == 0 ||
        memcmp(cmd_bfr, "Hc-1", 4) == 0 ||
        memcmp(cmd_bfr, "Hc0", 4) == 0 ||
        memcmp(cmd_bfr, "Hc1", 4) == 0)
        return gdb_reply("OK");
    gdb_reply("E01");
}

void gdb_stub::gdb_kill(void)
{
    if (!connected)
        return;

    gdb_ack();

    gdb_deinit();

    CPU::Stop();
    DEBUG_LOG(GDB_THREAD, "killed by gdb");
}

void gdb_stub::gdb_read_mem(void)
{
    if (!connected)
        return;

    u8 reply[GDB_BFR_MAX - 4] = { 0 };
    u32 addr, len;
    u32 i;

    gdb_ack();

    i = 1;
    addr = 0;
    while (cmd_bfr[i] != ',')
        addr = (addr << 4) | hex2char(cmd_bfr[i++]);

    i++;

    len = 0;
    while (i < cmd_len)
        len = (len << 4) | hex2char(cmd_bfr[i++]);
    DEBUG_LOG(GDB_THREAD, "gdb: read memory: %08x bytes from %08x\n", len, addr);

    if (len * 2 > sizeof reply)
        gdb_reply("E01");

    mem2hex(reply, addr, len);
    gdb_reply((char *)reply);
}

void gdb_stub::gdb_write_mem(void)
{
    if (!connected)
        return;

    u32 addr, len;
    u32 i;

    gdb_ack();

    i = 1;
    addr = 0;
    while (cmd_bfr[i] != ',')
        addr = (addr << 4) | hex2char(cmd_bfr[i++]);

    i++;

    len = 0;
    while (cmd_bfr[i] != ':')
        len = (len << 4) | hex2char(cmd_bfr[i++]);
    DEBUG_LOG(GDB_THREAD, "gdb: write memory: %08x bytes to %08x\n", len, addr);

    hex2mem(addr, cmd_bfr + i, len);
    gdb_reply("OK");
}

void gdb_stub::gdb_read_register(void)
{
    if (!connected)
        return;

    u8 reply[64] = { 0 };
    u32 id = 0;

    gdb_ack();

    u32 i = 1;
    while (i < cmd_len)
        id = (id << 4) | hex2char(cmd_bfr[i++]);

    if (0 <= id && id <= 31)
    {
        wbe32hex(reply, GPR(id));
    }
    else if (32 <= id && id <= 63)
    {
        wbe64hex(reply,      riPS1(id - 32));
        wbe64hex(reply + 16, riPS0(id - 32));
    }
    else
    {
        switch (id)
        {
        case 64:
            wbe32hex(reply, PC);
            break;
        case 65:
            wbe32hex(reply, MSR);
            break;
        case 66:
            wbe32hex(reply, GetCR());
            break;
        case 67:
            wbe32hex(reply, LR);
            break;
        case 68:
            wbe32hex(reply, CTR);
            break;
        case 69:
            wbe32hex(reply, XER);
            break;
        case 70:
            wbe32hex(reply, 0x0BADC0DE);
            break;
        case 71:
            wbe32hex(reply, FPSCR.Hex);
            break;
        default:
            return gdb_reply("E01");
            break;
        }
    }

    gdb_reply((char *)reply);
}

void gdb_stub::gdb_write_register(void)
{
    if (!connected)
        return;

    u32 id = 0;

    gdb_ack();

    u32 i = 1;
    while (cmd_bfr[i] != '=')
        id = (id << 4) | hex2char(cmd_bfr[i++]);
    ++i;

    u8 * bufptr = cmd_bfr + i;

    if (0 <= id && id <= 31)
    {
        GPR(id) = rbe32hex(bufptr);
    }
    else if (32 <= id && id <= 63)
    {
        riPS1(id - 32) = rbe64hex(bufptr);
        riPS0(id - 32) = rbe64hex(bufptr + 16);
    }
    else
    {
        switch (id)
        {
        case 64:
            PC = rbe32hex(bufptr);
            break;
        case 65:
            MSR = rbe32hex(bufptr);
            break;
        case 66:
            SetCR(rbe32hex(bufptr));
            break;
        case 67:
            LR = rbe32hex(bufptr);
            break;
        case 68:
            CTR = rbe32hex(bufptr);
            break;
        case 69:
            XER = rbe32hex(bufptr);
            break;
        case 70:
            // do nothing, we don't have MQ
            break;
        case 71:
            FPSCR.Hex = rbe32hex(bufptr);
            break;
        default:
            return gdb_reply("E01");
            break;
        }
    }

    gdb_reply("OK");
}

void gdb_stub::gdb_handle_query(void)
{
    if (!connected)
        return;

    DEBUG_LOG(GDB_THREAD, "gdb: query '%s'\n", cmd_bfr + 1);
    gdb_ack();
    gdb_reply("");
}

void gdb_stub::gdb_step(void)
{
    if (!connected)
        return;

    gdb_ack();

    if (PowerPC::CPU_STEPPING != PowerPC::GetState())
        return;

    PowerPC::SingleStep();
}

void gdb_stub::gdb_add_bp(void)
{
    if (!connected)
        return;

    u32 type = 0, addr = 0, len = 0, i = 1;

    gdb_ack();

    while (cmd_bfr[i] != ',')
        type = (type << 4) | hex2char(cmd_bfr[i++]);
    i++;

    switch (type)
    {
    case 0:
    case 1:
        type = GDB_BP_TYPE_X;
        break;
    case 2:
        type = GDB_BP_TYPE_W;
        break;
    case 3:
        type = GDB_BP_TYPE_R;
        break;
    case 4:
        type = GDB_BP_TYPE_A;
        break;
    default:
        return gdb_reply("E01");
    }

    addr = 0;
    len = 0;

    while (cmd_bfr[i] != ',')
        addr = (addr << 4) | hex2char(cmd_bfr[i++]);
    i++;

    while (i < cmd_len)
        len = (len << 4) | hex2char(cmd_bfr[i++]);

    gdb_bp_add(type, addr, len);
    gdb_reply("OK");
}

void gdb_stub::gdb_remove_bp(void)
{
    if (!connected)
        return;

    u32 type = 0, addr = 0, len = 0, i = 1;

    gdb_ack();

    while (cmd_bfr[i] != ',')
        type = (type << 4) | hex2char(cmd_bfr[i++]);
    i++;

    switch (type)
    {
    case 0:
    case 1:
        type = GDB_BP_TYPE_X;
        break;
    case 2:
        type = GDB_BP_TYPE_W;
        break;
    case 3:
        type = GDB_BP_TYPE_R;
        break;
    case 4:
        type = GDB_BP_TYPE_A;
        break;
    default:
        return gdb_reply("E01");
    }

    addr = 0;
    len = 0;

    while (cmd_bfr[i] != ',')
        addr = (addr << 4) | hex2char(cmd_bfr[i++]);
    i++;

    while (i < cmd_len)
        len = (len << 4) | hex2char(cmd_bfr[i++]);

    gdb_bp_remove(type, addr, len);
    gdb_reply("OK");
}

void gdb_stub::gdb_pause(void)
{
    if (!connected)
        return;

    gdb_ack();

    if (PowerPC::CPU_STEPPING != PowerPC::GetState())
    {
        CPU::EnableStepping(true);
    }
}

void gdb_stub::gdb_signal(u32 s, u64 addr, MemCheckCondition cond)
{
    sig = s;
    signal_addr = addr;
    signal_cond = cond;

    gdb_handle_signal();
}

void gdb_stub::gdb_bp_add(u32 type, u32 addr, u32 len)
{
    MemCheckCondition condition;
    bool is_mem_check = false;

    TMemCheck MemCheck;

    MemCheck.StartAddress = addr;
    MemCheck.EndAddress = addr + len;
    MemCheck.bRange = 1 < len;
    MemCheck.OnRead = false;
    MemCheck.OnWrite = false;
    MemCheck.Log = true;
    MemCheck.Break = true;

    switch (type)
    {
    case GDB_BP_TYPE_X:
    {
        is_mem_check = false;
    }
    break;
    case GDB_BP_TYPE_W:
    {
        is_mem_check = true;
        condition = MEMCHECK_WRITE;
    }
    break;
    case GDB_BP_TYPE_R:
    {
        is_mem_check = true;
        condition = MEMCHECK_READ;
    }
    break;
    case GDB_BP_TYPE_A:
    {
        is_mem_check = true;
        condition = MEMCHECK_READWRITE;
    }
    break;
    }

    if (is_mem_check)
    {
        PowerPC::memchecks.Add(MemCheck);
    }
    else
    {
        PowerPC::breakpoints.Add(addr & ~3);
    }

    DEBUG_LOG(GDB_THREAD, "gdb: added a %d breakpoint: %08x bytes at %08X\n", type, len, addr);
}

void gdb_stub::gdb_bp_remove(u32 type, u32 addr, u32 len)
{
    bool is_mem_check = false;

    switch (type)
    {
    case GDB_BP_TYPE_X:
    {
        is_mem_check = false;
    }
    break;
    case GDB_BP_TYPE_W:
    case GDB_BP_TYPE_R:
    case GDB_BP_TYPE_A:
    {
        is_mem_check = true;
    }
    break;
    }

    if (is_mem_check)
    {
        PowerPC::memchecks.Remove(addr);
    }
    else
    {
        PowerPC::breakpoints.Remove(addr);
    }

    DEBUG_LOG(GDB_THREAD, "gdb: removed a %d breakpoint: %08x bytes at %08X\n", type, len, addr);
}
