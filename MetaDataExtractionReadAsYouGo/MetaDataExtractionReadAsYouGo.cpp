// MetadataExtractorC++.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "MetadataExtractionReadAsYouGo.h"

void* MetadataEx::displayErrorString(
	DWORD error)
{
	LPVOID lpMsgBuf;
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

bool MetadataEx::openFile(
	const char* path,
	HANDLE& handle)
{
	handle = CreateFileA(
		path,                  // file to open
		GENERIC_READ,          // open for reading
		FILE_SHARE_READ,       // share for reading
		NULL,                  // default security
		OPEN_EXISTING,         // existing file only
		FILE_ATTRIBUTE_NORMAL, // normal file
		NULL);                 // no attr. template

	if (handle == INVALID_HANDLE_VALUE)
	{
		wchar_t* errorString = (wchar_t*)displayErrorString(GetLastError());
		std::wcout << "Unable to open file " << path <<
			" for reading, err: " << GetLastError() << ": " << errorString << "\n";
		LocalFree(errorString);
		return false;
	}

	return true;
}

bool MetadataEx::mapFile(
	HANDLE handle,
	BYTE*& buf)
{
	bool ret = false;
	void* start = NULL;
	HANDLE hMapFile;

	hMapFile = CreateFileMapping(
		handle,
		NULL,                    // default security
		PAGE_READONLY,           // read/write access
		0,                       // maximum object size (high-order DWORD)
		0,                       // maximum object size (low-order DWORD)
		NULL);                   // name of mapping object

	if (hMapFile == NULL)
	{
		wchar_t* errorString = (wchar_t*)displayErrorString(GetLastError());
		printf("Could not create file mapping object, err: %d, msg: '%S'\n",
			GetLastError(), errorString);
		LocalFree(errorString);
		return false;
	}

	start = (void*)MapViewOfFile(
		hMapFile,		// handle to map object
		FILE_MAP_READ,	// read permission
		0, 0, 0);

	if (start == NULL)
	{
		std::cout << "Could not map view of file, err: " <<
			GetLastError() << std::endl;
	}
	else
	{
		buf = (BYTE*)start;
		std::cout << "Successfully mapped file in process address space.\n";
		ret = true;
	}

	if ((hMapFile != 0) && (hMapFile != INVALID_HANDLE_VALUE))
		CloseHandle(hMapFile);

	return ret;
}

bool MetadataEx::loadFile(
	const std::string& path,
	BYTE*& buffer,
	uint32_t& fileSize)
{
	HANDLE handle;
	if (!openFile(path.c_str(), handle))
		return false;

	auto ret =  mapFile(handle, buffer);
	fileSize = GetFileSize(handle, NULL);

	if (handle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(handle);
		handle = INVALID_HANDLE_VALUE;
	}

	return ret;
}


bool MetadataEx::searchVersionInfoByName(
	const version_values_t& versionInfo,
	const std::wstring& key,
	std::wstring& value)
{
	auto found{ false };
	for (auto i : versionInfo)
	{
		
		if (wcsncmp(i.first.c_str(), key.c_str(), key.size()) == 0)
		{
			value = i.second;
			found = true;
		}
	}

	if (!found)
	{
		std::wcout << "Resource value " << key << " not found in VS_VERSIONINFO.\n";
	}
	return found;
}

bool MetadataEx::getVersionInformation(
	const std::string& fileName,
	versionInformationMap& entity)
{
	BYTE* fileData = nullptr;
	uint32_t fileSize = 0;
	version_values_t versionInfo;

	auto ret{ false };
	try
	{
		resource_section_info_t resourceSectionInfo{};
		PEParser parser;

		ret = loadFile(fileName, fileData, fileSize);
		CHECK_RET_CODE(ret, "loadFile failed");

		ret = ret && parser.parse(fileName, fileData, fileSize);
		CHECK_RET_CODE(ret, "parse failed");

		ret = ret && parser.parseResourceDir(RT_VERSION, resourceSectionInfo);
		CHECK_RET_CODE(ret, "parseResourceDir failed");

		ret = ret && parser.parseVersionInfo(resourceSectionInfo, versionInfo);
		CHECK_RET_CODE(ret, "parseVersionInfo failed");
	}

	catch (const std::exception & ex)
	{
		std::cout << "Caught exception: " << ex.what() << std::endl;
	}

#ifdef _DEBUG
	std::cout << "\nPrinting everything ==>\n";
	for (auto i : versionInfo)
	{
		std::wcout << i.first << " = " << i.second << std::endl;
	}
	std::cout << "\n";
#endif

	if (!versionInfo.empty())
	{
		UPDATE_VERSION_INFO(versionInfo, std::wstring(ORIGINAL_FILENAME_STRING),
			ITEM_ID_VERSION_RESOURCE_ORIGINAL_FILE_NAME, entity);

		UPDATE_VERSION_INFO(versionInfo, std::wstring(COMPANY_NAME_STRING),
			ITEM_ID_VERSION_RESOURCE_COMPANY_NAME, entity);

		UPDATE_VERSION_INFO(versionInfo, std::wstring(PRODUCT_NAME_STRING),
			ITEM_ID_VERSION_RESOURCE_PRODUCT_NAME, entity);

		UPDATE_VERSION_INFO(versionInfo, std::wstring(PRODUCT_VERSION_STRING),
			ITEM_ID_VERSION_RESOURCE_PRODUCT_VERSION, entity);

		UPDATE_VERSION_INFO(versionInfo, std::wstring(FILE_VERSION_STRING),
			ITEM_ID_VERSION_RESOURCE_FILE_VERSION, entity);
	}
out:
	return ret;
}
