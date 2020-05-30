#include "File.h"

void* displayErrorString(
	DWORD error)
{
	LPVOID lpMsgBuf; <-- DJ: Convert this to std::unique_ptr with custom deleter that calls LocalFree()
	if (!FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		error,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)& lpMsgBuf,
		0,
		NULL))
	{
		return NULL;
	}

	return lpMsgBuf;
}

/********************* File ******************/
<-- If this calss is unusable without opening handle to the file, open it in constructor itself and throw exception if it 
can't be opened. Read about RAII principle(Resource acquisition is Initialization) 
File::File(const std::string& file) 
	m_handle{ INVALID_HANDLE_VALUE },
	m_currentPosition{ 0 }
{};

bool File::open(void)
{
	m_handle = CreateFileA(
		m_fileName.c_str(),    // file to open
		GENERIC_READ,          // open for reading
		FILE_SHARE_READ,       // share for reading
		NULL,                  // default security
		OPEN_EXISTING,         // existing file only
		FILE_ATTRIBUTE_NORMAL, // normal file
		NULL);                 // no attr. template

	if (m_handle == INVALID_HANDLE_VALUE)
	{
		wchar_t* errorString = (wchar_t*)displayErrorString(GetLastError());
		std::wcout << "Unable to open file " << m_fileName.c_str() <<
			" for reading, err: " << GetLastError() << ": " << errorString << "\n";
		LocalFree(errorString);
		return false;
	}

	return true;
}

bool File::isOpened(void)
{
	return (m_handle != INVALID_HANDLE_VALUE);
}

bool File::read(
	void* buf,
	const DWORD bytesToRead)
{
	DWORD bytesRead = 0;
	if (!ReadFile(m_handle, buf, bytesToRead, &bytesRead, NULL))
	{
		wchar_t* errorString = (wchar_t*)displayErrorString(GetLastError());
		std::wcout << "Unable to read file " << m_fileName.c_str() <<
			" for reading, err: " << GetLastError() << ": " << errorString << "\n";
		LocalFree(errorString);
		return false;
	}

	//std::cout << "readFile read " << bytesRead << " bytes, for handle: " << m_handle << "\n";
	if (bytesRead != bytesToRead)
	{
		std::cout << "Warning: Unable to read " << bytesToRead <<
			" bytes. Could only read " << bytesRead << "\n";
	}
	return true;
}

bool File::seekStart(
	long offset)
{
	if (SetFilePointer(m_handle, offset, NULL, FILE_BEGIN)
		== INVALID_SET_FILE_POINTER)
	{
		wchar_t* errorString = (wchar_t*)displayErrorString(GetLastError());
		std::wcout << "Unable to seek file " << m_fileName.c_str() <<
			" to position " << offset << ", err: " << GetLastError() <<
			": " << errorString << "\n";
		LocalFree(errorString);
		return false;
	}

	//std::cout << "Seeked to position: " << offset << std::endl;
	m_currentPosition = offset;
	return true;
}
