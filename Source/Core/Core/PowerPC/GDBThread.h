// Copyright 2013 Dolphin Emulator Project
// Licensed under GPLv2+
// Refer to the license.txt file included.

// Originally written by Sven Peter <sven@fail0verflow.com> for anergistic.

#pragma once

#include <signal.h>

#include "Common/CommonTypes.h"
#include "Common/Thread.h"
#include "Common/Event.h"

#include "Core/HW/CPU.h"
#include "Core/HW/Memmap.h"
#include "Core/PowerPC/PowerPC.h"

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

#define		GDB_BFR_MAX	10000

// --------------------------------------------------------------------------------------
//  GDBThread
// --------------------------------------------------------------------------------------
// Threaded wrapper class for implementing debugging functionality through a gdb stub.
//
class GDBThread
{
public:
    GDBThread();
    ~GDBThread();

    bool Initialize();
    void Terminate();

protected:
    void OnStart();
    void OnStop();
    void OnPause();
    void OnResume();
    void UpdateState(PowerPC::CPUState current_state);

    void ExecuteTaskInThread();

protected:
    bool is_running;

    std::thread server_thread;

    PowerPC::CPUState previous_state;

protected:
    void gdb_init(u32 port);
#ifndef _WIN32
    void gdb_init_local(const char *socket);
#endif
    void gdb_deinit();

    bool gdb_active();

    int gdb_data_available();

    void gdb_handle_events();

    void gdb_signal(u32 s, u64 addr = -1, MemCheckCondition cond = MEMCHECK_NONE);

protected:
    bool connected;
    int tmpsock = -1;
    int sock = -1;
    struct sockaddr_in saddr_server, saddr_client;

    u8 cmd_bfr[GDB_BFR_MAX + 1];
    u32 cmd_len;

    u32 sig;
    u64 signal_addr;
    MemCheckCondition signal_cond;

protected:
    void gdb_init_generic(int domain,
        const sockaddr *server_addr, socklen_t server_addrlen,
        sockaddr *client_addr, socklen_t *client_addrlen);

    void gdb_read_command();
    void gdb_parse_command();

    u8 gdb_read_byte();
    u8 gdb_calc_chksum();

    void gdb_reply(const char *reply);
    void gdb_nak();
    void gdb_ack();

    void gdb_handle_signal();

    void gdb_continue();

    void gdb_detach();

    void gdb_read_registers();
    void gdb_write_registers();

    void gdb_handle_set_thread();

    void gdb_kill();

    void gdb_read_mem();
    void gdb_write_mem();

    void gdb_read_register();
    void gdb_write_register();

    void gdb_handle_query();

    void gdb_step();

    void gdb_add_bp();
    void gdb_remove_bp();

    void gdb_pause();

    void gdb_bp_add(u32 type, u32 addr, u32 len);
    void gdb_bp_remove(u32 type, u32 addr, u32 len);
};
