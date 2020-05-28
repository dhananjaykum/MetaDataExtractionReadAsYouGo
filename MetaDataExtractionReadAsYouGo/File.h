#pragma once
#include <iostream>
#include <windows.h>

class File
{
public:
	File(const std::string& file);

	bool open(void);
	bool isOpened(void);

	bool read(
		void* buf,
		const DWORD bufSize);

	bool seekStart(
		const long offset);

	const std::string& getName() const
	{
		return m_fileName;
	}

private:
	std::string m_fileName;
	HANDLE m_handle;
	size_t m_currentPosition;
};
