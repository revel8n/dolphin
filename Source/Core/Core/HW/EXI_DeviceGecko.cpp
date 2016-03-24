// Copyright 2011 Dolphin Emulator Project
// Licensed under GPLv2+
// Refer to the license.txt file included.

#include <atomic>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

#include "Common/ChunkFile.h"
#include "Common/CommonFuncs.h"
#include "Common/CommonTypes.h"
#include "Common/StringUtil.h"
#include "Common/Thread.h"
#include "Common/Logging/Log.h"
#include "Core/Core.h"
#include "Core/HW/EXI_DeviceGecko.h"
#include "Core/HW/CPU.h"
#include "Core/PowerPC/PowerPC.h"
#include "Core/PowerPC/Interpreter/Interpreter_FPUtils.h"
#include "Core/Core.h"

u16                       GeckoSockServer::server_port;
int                       GeckoSockServer::client_count;
std::thread               GeckoSockServer::connectionThread;
std::atomic<bool>         GeckoSockServer::server_running;
std::mutex                GeckoSockServer::connection_lock;
std::queue<std::unique_ptr<sf::TcpSocket>> GeckoSockServer::waiting_socks;

GeckoSockServer::GeckoSockServer()
	: client_running(false)
{
	if (!connectionThread.joinable())
		connectionThread = std::thread(GeckoConnectionWaiter);

	clientThread = std::thread(std::mem_fun(&GeckoSockServer::ClientThread), this);
}

GeckoSockServer::~GeckoSockServer()
{
	if (clientThread.joinable())
		--client_count;

	process_commands = false;
	if (commandThread.joinable())
		commandThread.join();

	client_running = false;
	if (clientThread.joinable())
		clientThread.join();

	if (client_count <= 0)
	{
		server_running = false;
		if (connectionThread.joinable())
			connectionThread.join();
	}
}

void GeckoSockServer::GeckoConnectionWaiter()
{
	Common::SetCurrentThreadName("Gecko Connection Waiter");

	sf::TcpListener server;
	server_port = 0xd6ec; // "dolphin gecko"
	for (int bind_tries = 0; bind_tries <= 10 && !server_running; bind_tries++)
	{
		server_running = server.listen(server_port) == sf::Socket::Done;
		if (!server_running)
			server_port++;
	}

	if (!server_running)
		return;

	Core::DisplayMessage(
		StringFromFormat("USBGecko: Listening on TCP port %u", server_port),
		5000);

	server.setBlocking(false);

	auto new_client = std::make_unique<sf::TcpSocket>();
	while (server_running)
	{
		if (server.accept(*new_client) == sf::Socket::Done)
		{
			std::lock_guard<std::mutex> lk(connection_lock);
			waiting_socks.push(std::move(new_client));

			new_client = std::make_unique<sf::TcpSocket>();
		}

		Common::SleepCurrentThread(1);
	}
}

bool GeckoSockServer::GetAvailableSock()
{
	bool sock_filled = false;

	std::lock_guard<std::mutex> lk(connection_lock);

	if (!waiting_socks.empty())
	{
		client = std::move(waiting_socks.front());
		if (commandThread.joinable())
		{
			process_commands = false;
			commandThread.join();
		}
		if (clientThread.joinable())
		{
			//client_running = false;
			//clientThread.join();

			recv_fifo = std::deque<u8>();
			send_fifo = std::deque<u8>();
		}
		//clientThread = std::thread(&GeckoSockServer::ClientThread, this);
		commandThread = std::thread(&GeckoSockServer::CommandThread, this);
		//client_count++;
		waiting_socks.pop();
		sock_filled = true;
	}

	return sock_filled;
}

void GeckoSockServer::ClientThread()
{
	client_count++;
	client_running = true;

	Common::SetCurrentThreadName("Gecko Client");

	if (IsClientValid())
	{
		client->setBlocking(false);
	}

	while (client_running)
	{
		bool did_nothing = true;

		if (!IsClientValid() && GetAvailableSock())
		{
			client->setBlocking(false);
		}

		if (IsClientValid())
		{
			// what's an ideal buffer size?
			char data[128];
			std::size_t got = 0;

			if (client->receive(&data[0], ArraySize(data), got) == sf::Socket::Disconnected)
			{
				//client_running = false;
				process_commands = false;
				if (commandThread.joinable())
					commandThread.join();
				client->disconnect();
				continue;
			}

			if (got != 0)
			{
				did_nothing = false;

				NOTICE_LOG(EXPANSIONINTERFACE, "Received %ld byte(s)", (u64)got);

				std::lock_guard<std::mutex> lk(transfer_lock);

				recv_fifo.insert(recv_fifo.end(), &data[0], &data[got]);
			}

			std::vector<char> packet;

			{
				std::lock_guard<std::mutex> lk(transfer_lock);

				if (!send_fifo.empty())
				{
					did_nothing = false;

					packet.assign(send_fifo.begin(), send_fifo.end());
					send_fifo.clear();
				}
			}

			if (!packet.empty())
			{
				did_nothing = false;

				NOTICE_LOG(EXPANSIONINTERFACE, "Sending %ld byte(s): 0x%02X", (u64)packet.size(), (u8) packet[0]);

				if (client->send(&packet[0], packet.size()) == sf::Socket::Disconnected)
				{
					//client_running = false;
					process_commands = false;
					if (commandThread.joinable())
						commandThread.join();
					client->disconnect();
					continue;
				}
			}
		}	// unlock transfer

		if (did_nothing)
			Common::YieldCPU();
	}

	process_commands = false;

	client_count--;
	if (IsClientValid())
		client->disconnect();
}

template<typename T>
bool GeckoSockServer::read_data(T& data)
{
	return read_data((u8*)&data, sizeof(T));
}

template<typename T>
bool GeckoSockServer::read_data(std::vector<T>& data)
{
	return read_data((u8*) &data.front(), sizeof(T) * data.size());
}

bool GeckoSockServer::read_data(u8* data, u64 size)
{
	while (process_commands)
	{
		{
			std::lock_guard<std::mutex> lk(transfer_lock);
			if (recv_fifo.size() >= size)
			{
				memcpy_s(data, size, &recv_fifo.front(), size);

				recv_fifo.erase(recv_fifo.begin(), recv_fifo.begin() + size);

				return true;
			}
		}
		Common::YieldCPU();
	}

	return false;
}

template<typename T>
bool GeckoSockServer::write_data(const T& data)
{
	return write_data((u8*) &data, sizeof(T));
}

template<typename T>
bool GeckoSockServer::write_data(const std::vector<T>& data)
{
	return write_data((u8*) &data.front(), sizeof(T) * data.size());
}

bool GeckoSockServer::write_data(const u8* data, u64 size)
{
	if (process_commands)
	{
		std::lock_guard<std::mutex> lk(transfer_lock);
		send_fifo.insert(send_fifo.end(), data, data + size);

		return true;
	}

	return false;
}

void GeckoSockServer::SetMemCheck(u32 startAddress, u32 endAddress, u32 type)
{
	TMemCheck MemCheck;

	MemCheck.StartAddress = startAddress;
	MemCheck.EndAddress = endAddress;
	MemCheck.bRange = startAddress != endAddress;
	MemCheck.OnRead = false;
	MemCheck.OnWrite = false;
	MemCheck.Log = true;
	MemCheck.Break = true;

	switch (type)
	{
	case BPRead:
		MemCheck.OnRead = true;
		break;
	case BPWrite:
		MemCheck.OnWrite = true;
		break;
	case BPReadWrite:
		MemCheck.OnRead = true;
		MemCheck.OnWrite = true;
		break;
	default:
		return;
		break;
	}

	PowerPC::memchecks.Add(MemCheck);
}

void GeckoSockServer::CommandThread()
{
	process_commands = true;

	Common::SetCurrentThreadName("Gecko Commands");

	while (process_commands)
	{
		bool did_nothing = true;

		u8 command = 0;
		if (read_data(command))
		{
			did_nothing = false;

			switch (command)
			{
			case cmd_poke08:
			{
				NOTICE_LOG(EXPANSIONINTERFACE, "cmd_poke08");

				u32 address = 0;
				u32 value = 0;

				read_data(address);
				read_data(value);

				address = Common::swap32(address);
				value = Common::swap32(value);

				PowerPC::Write_U8(value, address);
			}
				break;

			case cmd_poke16:
			{
				NOTICE_LOG(EXPANSIONINTERFACE, "cmd_poke16");

				u32 address = 0;
				u32 value = 0;

				read_data(address);
				read_data(value);

				address = Common::swap32(address);
				value = Common::swap32(value);

				PowerPC::Write_U16(value, address);
			}
				break;

			case cmd_pokemem:
			{
				NOTICE_LOG(EXPANSIONINTERFACE, "cmd_pokemem");

				u32 address = 0;
				u32 value = 0;

				read_data(address);
				read_data(value);

				address = Common::swap32(address);
				value = Common::swap32(value);

				PowerPC::Write_U32(value, address);
			}
				break;

			case cmd_readmem:
			{
				NOTICE_LOG(EXPANSIONINTERFACE, "cmd_readmem");

				u32 l_address = 0;
				u32 h_address = 0;

				write_data(GCACK);

				read_data(l_address);
				read_data(h_address);

				l_address = Common::swap32(l_address);
				h_address = Common::swap32(h_address);

				NOTICE_LOG(EXPANSIONINTERFACE, "0x%08X -> 0x%08X", l_address, h_address);

				u32 address_range = h_address - l_address;
				u32 data_packet_count = address_range / packetsize;
				u32 last_packet_size = address_range % packetsize;

				std::vector<u8> packet(packetsize);

				bool send_packets = true;

				u32 address = l_address;

				u8 result = 0;
				while (data_packet_count > 0 && send_packets)
				{
					std::string data = PowerPC::Read(address, packetsize);

					if (!data.empty())
						std::copy(data.begin(), data.end(), packet.begin());

					write_data(packet);

					read_data(result);
					switch (result)
					{
					case GCACK:
						address += packetsize;
						--data_packet_count;
						break;
					case GCRETRY:
						break;
					case GCFAIL:
					default:
						send_packets = false;
						break;
					}
				}
				while (last_packet_size > 0 && send_packets)
				{
					std::string data = PowerPC::Read(address, last_packet_size);

					if (!data.empty())
						std::copy(data.begin(), data.end(), packet.begin());

					write_data(&packet.front(), last_packet_size);

					read_data(result);
					switch (result)
					{
					case GCRETRY:
						break;
					case GCACK:
					case GCFAIL:
					default:
						send_packets = false;
						break;
					}
				}
			}
				break;

			case cmd_pause:
			{
				NOTICE_LOG(EXPANSIONINTERFACE, "cmd_pause");

				CPU::EnableStepping(true);
			}
				break;

			case cmd_unfreeze:
			{
				NOTICE_LOG(EXPANSIONINTERFACE, "cmd_unfreeze");

				CPU::EnableStepping(false);
			}
				break;

			case cmd_breakpoint:
			{
				NOTICE_LOG(EXPANSIONINTERFACE, "cmd_breakpoint");

				u32 address = 0;

				read_data(address);

				address = Common::swap32(address);

				u32 type = address & 7;
				address &= ~7;
				SetMemCheck(address, address + 8, type);
			}
				break;

			case cmd_breakpointx:
			{
				NOTICE_LOG(EXPANSIONINTERFACE, "cmd_breakpointx");

				u32 address = 0;

				read_data(address);

				address = Common::swap32(address);

				PowerPC::breakpoints.Add(address & ~3);
			}
				break;

			case cmd_sendregs:
			{
				NOTICE_LOG(EXPANSIONINTERFACE, "cmd_sendregs");

				std::vector<u32> regs(40);

				write_data(GCACK);

				read_data(regs);
			}
				break;

			case cmd_getregs:
			{
				NOTICE_LOG(EXPANSIONINTERFACE, "cmd_getregs");

				std::vector<u32> regs(72);

				regs[0] = GetCR();
				regs[1] = XER;
				regs[2] = CTR;
				regs[3] = DSISR;
				regs[4] = DAR;
				regs[5] = SRR0;
				regs[6] = SRR1;
				for (size_t i = 0; i < 32; i++)
				{
					regs[i + 7] = GPR(i);
				}
				regs[39] = LR;
				for (size_t i = 0; i < 32; i++)
				{
					regs[i + 40] = ConvertToSingle(riPS0(i));
				}

				for (size_t i = 0; i < regs.size(); i++)
				{
					regs[i] = Common::swap32(regs[i]);
				}

				write_data(regs);
			}
				break;

			case cmd_cancelbp:
			{
				NOTICE_LOG(EXPANSIONINTERFACE, "cmd_cancelbp");

			}
				break;

			case cmd_sendcheats:
			{
				NOTICE_LOG(EXPANSIONINTERFACE, "cmd_sendcheats");

				u32 length = 0;

				write_data(GCACK);

				read_data(length);

				length = Common::swap32(length);

				u32 data_packet_count = length / uplpacketsize;
				u32 last_packet_size = length % uplpacketsize;

				std::vector<u8> packet(uplpacketsize);

				bool read_packets = true;

				u8 result = 0;
				while (data_packet_count > 0 && read_packets)
				{
					if (read_data(packet))
					{
						write_data(GCACK);
						--data_packet_count;
					}
				}
				while (last_packet_size > 0 && read_packets)
				{
					if (read_data(&packet.front(), last_packet_size))
					{
						write_data(GCACK);
					}
				}
			}
				break;

			case cmd_upload:
			{
				NOTICE_LOG(EXPANSIONINTERFACE, "cmd_upload");

				u32 l_address = 0;
				u32 h_address = 0;

				write_data(GCACK);

				read_data(l_address);
				read_data(h_address);

				l_address = Common::swap32(l_address);
				h_address = Common::swap32(h_address);

				NOTICE_LOG(EXPANSIONINTERFACE, "0x%08X -> 0x%08X", l_address, h_address);

				u32 address_range = h_address - l_address;
				u32 data_packet_count = address_range / uplpacketsize;
				u32 last_packet_size = address_range % uplpacketsize;

				std::vector<u8> packet(uplpacketsize);

				bool read_packets = true;

				u32 c_address = l_address;

				u8 result = 0;
				while (data_packet_count > 0 && read_packets)
				{
					read_data(packet);

					for (int i = 0; i < packet.size(); ++i)
					{
						PowerPC::Write_U8(packet[i], c_address + i);
					}

					read_data(result);
					switch (result)
					{
					case GCACK:
						--data_packet_count;
						c_address += uplpacketsize;
						break;
					case GCRETRY:
						break;
					case GCFAIL:
					default:
						read_packets = false;
						break;
					}
				}
				while (last_packet_size > 0 && read_packets)
				{
					read_data(&packet.front(), last_packet_size);

					for (int i = 0; i < packet.size(); ++i)
					{
						PowerPC::Write_U8(packet[i], c_address + i);
					}

					read_data(result);
					switch (result)
					{
					case GCRETRY:
						break;
					case GCACK:
						c_address += last_packet_size;
					case GCFAIL:
					default:
						read_packets = false;
						break;
					}
				}
			}
				break;

			case cmd_hook + 0:
			case cmd_hook + 1:
			//case cmd_hook + 2:
			//case cmd_hookpause + 0:
			//case cmd_hookpause + 1:
			case cmd_hookpause + 2:
			{
				NOTICE_LOG(EXPANSIONINTERFACE, "cmd_hook");

				u8 language = 0;
				u8 patches = 0;

				read_data(language);
				read_data(patches);
			}
				break;

			case cmd_step:
			{
				NOTICE_LOG(EXPANSIONINTERFACE, "cmd_step");

				PowerPC::SingleStep();
			}
				break;

			case cmd_status:
			{
				NOTICE_LOG(EXPANSIONINTERFACE, "cmd_status");

				switch (PowerPC::GetState())
				{
				case PowerPC::CPU_RUNNING:
					write_data(WiiStatus::Running);
					break;

				case PowerPC::CPU_STEPPING:
					if (PowerPC::breakpoints.IsAddressBreakPoint(PC))
						write_data(WiiStatus::Breakpoint);
					else
						write_data(WiiStatus::Paused);
					break;

				default:
					write_data(WiiStatus::Unknown);
					break;
				}
			}
				break;

			case cmd_cheatexec:
			{
				NOTICE_LOG(EXPANSIONINTERFACE, "cmd_cheatexec");

			}
				break;

			case cmd_nbreakpoint:
			{
				NOTICE_LOG(EXPANSIONINTERFACE, "cmd_nbreatpoint");

				u32 l_address = 0;
				u32 h_address = 0;

				read_data(l_address);
				read_data(h_address);

				l_address = Common::swap32(l_address);
				h_address = Common::swap32(h_address);

				NOTICE_LOG(EXPANSIONINTERFACE, "0x%08X -> 0x%08X", l_address, h_address);

				u32 type = l_address & 7;
				SetMemCheck(h_address, h_address, type);
			}
				break;

			case cmd_version:
			{
				NOTICE_LOG(EXPANSIONINTERFACE, "cmd_version");

				write_data(GCNewVer);
			}
				break;

			case GCACK:
				NOTICE_LOG(EXPANSIONINTERFACE, "GCACK");
				break;
			case GCRETRY:
				NOTICE_LOG(EXPANSIONINTERFACE, "GCRETRY");
				break;
			case GCFAIL:
				NOTICE_LOG(EXPANSIONINTERFACE, "GCFAIL");
				break;

			default:
				break;
			}

		}

		Common::YieldCPU();
	}
}

void CEXIGecko::ImmReadWrite(u32 &_uData, u32 _uSize)
{
	// We don't really care about _uSize
	(void)_uSize;

	if (!IsClientValid())
		GetAvailableSock();

	switch (_uData >> 28)
	{
	case CMD_LED_OFF:
		Core::DisplayMessage(
			"USBGecko: No LEDs for you!",
			3000);
		break;
	case CMD_LED_ON:
		Core::DisplayMessage(
			"USBGecko: A piercing blue light is now shining in your general direction",
			3000);
		break;

	case CMD_INIT:
		_uData = ident;
		break;

		// PC -> Gecko
		// |= 0x08000000 if successful
	case CMD_RECV:
		{
		std::lock_guard<std::mutex> lk(transfer_lock);
		if (!recv_fifo.empty())
		{
			_uData = 0x08000000 | (recv_fifo.front() << 16);
			recv_fifo.pop_front();
		}
		break;
		}

		// Gecko -> PC
		// |= 0x04000000 if successful
	case CMD_SEND:
		{
		std::lock_guard<std::mutex> lk(transfer_lock);
		send_fifo.push_back(_uData >> 20);
		_uData = 0x04000000;
		break;
		}

		// Check if ok for Gecko -> PC, or FIFO full
		// |= 0x04000000 if FIFO is not full
	case CMD_CHK_TX:
		_uData = 0x04000000;
		break;

		// Check if data in FIFO for PC -> Gecko, or FIFO empty
		// |= 0x04000000 if data in recv FIFO
	case CMD_CHK_RX:
		{
		std::lock_guard<std::mutex> lk(transfer_lock);
		_uData = recv_fifo.empty() ? 0 : 0x04000000;
		break;
		}

	default:
		ERROR_LOG(EXPANSIONINTERFACE, "Unknown USBGecko command %x", _uData);
		break;
	}
}

bool GeckoSockServer::IsClientValid() const
{
	return (nullptr != client && client->getLocalPort() != 0);
}
