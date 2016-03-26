// Copyright 2008 Dolphin Emulator Project
// Licensed under GPLv2+
// Refer to the license.txt file included.

#pragma once

#include <string>
#include <vector>

#include "Common/CommonTypes.h"

class DebugInterface;

enum MemCheckCondition
{
    MEMCHECK_NONE = 0x00,
    MEMCHECK_READ = 0x01,
    MEMCHECK_WRITE = 0x02,
    MEMCHECK_READWRITE = 0x03,
};

struct TBreakPoint
{
	u32  iAddress;
	bool bOn;
	bool bTemporary;
};

struct TMemCheck
{
	TMemCheck()
	{
		numHits = 0;
		StartAddress = EndAddress = 0;
		bRange = OnRead = OnWrite = Log = Break = false;
	}

	u32 StartAddress;
	u32 EndAddress;

	bool bRange;

	bool OnRead;
	bool OnWrite;

	bool Log;
	bool Break;

	u32 numHits;

	// returns whether to break
	bool Action(DebugInterface* dbg_interface, u32 _iValue, u32 addr,
	            bool write, int size, u32 pc);
};

struct TWatch
{
	std::string name = "";
	u32  iAddress;
	bool bOn;
};

// Code breakpoints.
class BreakPoints
{
public:
	typedef std::vector<TBreakPoint> TBreakPoints;
	typedef std::vector<std::string> TBreakPointsStr;

	const TBreakPoints& GetBreakPoints() { return m_BreakPoints; }

	TBreakPointsStr GetStrings() const;
	void AddFromStrings(const TBreakPointsStr& bps);

	// is address breakpoint
	bool IsAddressBreakPoint(u32 address) const;
	bool IsTempBreakPoint(u32 address) const;

	// Add BreakPoint
	void Add(u32 em_address, bool temp = false);
	void Add(const TBreakPoint& bp);

	// Remove Breakpoint
	void Remove(u32 _iAddress);
	void Clear();
	void ClearAllTemporary();

    void SetBreakpointTriggered(bool b, u64 addr = -1, MemCheckCondition cond = MEMCHECK_NONE)
    {
        breakpointTriggered_ = b;
        breakpointAddress_ = addr;
        breakpointCondition_ = cond;
    };
    bool GetBreakpointTriggered() { return breakpointTriggered_; };
    bool GetBreakpointTriggered(u64& addr, MemCheckCondition& cond)
    {
        addr = breakpointAddress_;
        cond = breakpointCondition_;
        return breakpointTriggered_;
    };

private:
	TBreakPoints m_BreakPoints;

    bool breakpointTriggered_;
    u64 breakpointAddress_;
    MemCheckCondition breakpointCondition_;
};


// Memory breakpoints
class MemChecks
{
public:
	typedef std::vector<TMemCheck> TMemChecks;
	typedef std::vector<std::string> TMemChecksStr;

	TMemChecks m_MemChecks;

	const TMemChecks& GetMemChecks() { return m_MemChecks; }

	TMemChecksStr GetStrings() const;
	void AddFromStrings(const TMemChecksStr& mcs);

	void Add(const TMemCheck& _rMemoryCheck);

	// memory breakpoint
	TMemCheck* GetMemCheck(u32 address);
	void Remove(u32 _Address);

	void Clear() { m_MemChecks.clear(); }

	bool HasAny() const { return !m_MemChecks.empty(); }
};

class Watches
{
public:
	typedef std::vector<TWatch> TWatches;
	typedef std::vector<std::string> TWatchesStr;

	const TWatches& GetWatches() { return m_Watches; }

	TWatchesStr GetStrings() const;
	void AddFromStrings(const TWatchesStr& bps);

	bool IsAddressWatch(u32 _iAddress) const;

	// Add BreakPoint
	void Add(u32 em_address);
	void Add(const TWatch& bp);

	void Update(int count, u32 em_address);
	void UpdateName(int count, const std::string name);

	// Remove Breakpoint
	void Remove(u32 _iAddress);
	void Clear();

private:
	TWatches m_Watches;
};
