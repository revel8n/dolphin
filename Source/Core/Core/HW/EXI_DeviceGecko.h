// Copyright 2008 Dolphin Emulator Project
// Licensed under GPLv2+
// Refer to the license.txt file included.

#pragma once

#include <atomic>
#include <deque>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>
#include <SFML/Network.hpp>

#include "Common/CommonTypes.h"
#include "Core/HW/EXI_Device.h"

class GeckoSockServer
{
public:
	GeckoSockServer();
	~GeckoSockServer();
	bool GetAvailableSock();

	// Client for this server object
	std::unique_ptr<sf::TcpSocket> client;
	void ClientThread();
	void CommandThread();
	std::thread clientThread;
	std::thread commandThread;
	std::mutex transfer_lock;

	std::deque<u8> send_fifo;
	std::deque<u8> recv_fifo;

private:
	static int        client_count;
	std::atomic<bool> client_running;

	// Only ever one server thread
	static void GeckoConnectionWaiter();

	static u16                       server_port;
	static std::atomic<bool>         server_running;
	static std::thread               connectionThread;
	static std::mutex                connection_lock;
	static std::queue<std::unique_ptr<sf::TcpSocket>> waiting_socks;

public:
	template<typename T>
	bool read_data(T& data);
	template<typename T>
	bool read_data(std::vector<T>& data);
	bool read_data(u8* data, u64 size);

	template<typename T>
	bool write_data(const T& data);
	template<typename T>
	bool write_data(const std::vector<T>& data);
	bool write_data(const u8* data, u64 size);

protected:

	bool IsClientValid() const;
	static void SetMemCheck(u32 startAddress, u32 endAddress, u32 type);

private:
	enum class WiiStatus : u8
	{
		Running,
		Paused,
		Breakpoint,
		Loader,
		Unknown
	};

	static const u32 packetsize = 0xF800;
	static const u32 uplpacketsize = 0xF80;

	static const u8 cmd_poke08 = 0x01;
	static const u8 cmd_poke16 = 0x02;
	static const u8 cmd_pokemem = 0x03;
	static const u8 cmd_readmem = 0x04;
	static const u8 cmd_pause = 0x06;
	static const u8 cmd_unfreeze = 0x07;
	static const u8 cmd_breakpoint = 0x09;
	static const u8 cmd_breakpointx = 0x10;
	static const u8 cmd_sendregs = 0x2F;
	static const u8 cmd_getregs = 0x30;
	static const u8 cmd_cancelbp = 0x38;
	static const u8 cmd_sendcheats = 0x40;
	static const u8 cmd_upload = 0x41;
	static const u8 cmd_hook = 0x42;
	static const u8 cmd_hookpause = 0x43;
	static const u8 cmd_step = 0x44;
	static const u8 cmd_status = 0x50;
	static const u8 cmd_cheatexec = 0x60;
	static const u8 cmd_nbreakpoint = 0x89;
	static const u8 cmd_version = 0x99;

	static const u8 GCBPHit = 0x11;
	static const u8 GCACK = 0xAA;
	static const u8 GCRETRY = 0xBB;
	static const u8 GCFAIL = 0xCC;
	static const u8 GCDONE = 0xFF;

	static const u8 GCNewVer = 0x80;

	static const u8 BPExecute = 0x03;
	static const u8 BPRead = 0x05;
	static const u8 BPWrite = 0x06;
	static const u8 BPReadWrite = 0x07;

	std::atomic<bool> process_commands;
};

class CEXIGecko
	: public IEXIDevice
	, private GeckoSockServer
{
public:
	CEXIGecko() {}
	bool IsPresent() const override { return true; }
	void ImmReadWrite(u32 &_uData, u32 _uSize) override;

private:
	enum
	{
		CMD_LED_OFF = 0x7,
		CMD_LED_ON  = 0x8,
		CMD_INIT    = 0x9,
		CMD_RECV    = 0xa,
		CMD_SEND    = 0xb,
		CMD_CHK_TX  = 0xc,
		CMD_CHK_RX  = 0xd,
	};

	static const u32 ident = 0x04700000;
};
