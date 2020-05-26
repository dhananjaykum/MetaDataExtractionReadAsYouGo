#pragma once
#include <Windows.h>
#include <map>
#include "PEParser.h"

#define ORIGINAL_FILENAME_STRING	L"OriginalFilename"
#define COMPANY_NAME_STRING			L"CompanyName"
#define FILE_VERSION_STRING			L"FileVersion"
#define PRODUCT_NAME_STRING			L"ProductName"
#define PRODUCT_VERSION_STRING		L"ProductVersion"

#define CHECK_RET_CODE(ret,ERR)\
do {\
if (!ret)\
{\
std::cout << "Failed to parse: " << ERR << std::endl; \
goto out;\
}\
}while(0)

#define UPDATE_VERSION_INFO(versionInfo,key,ItemID,entity)\
do{\
    std::wstring value;\
    if (searchVersionInfoByName((versionInfo), (key), value))\
	{\
		entity.emplace((ItemID), value);\
	}\
}while(0)
typedef enum
{
	ITEM_ID_VERSION_RESOURCE_ORIGINAL_FILE_NAME = 1,
	ITEM_ID_VERSION_RESOURCE_COMPANY_NAME,
	ITEM_ID_VERSION_RESOURCE_PRODUCT_NAME,
	ITEM_ID_VERSION_RESOURCE_PRODUCT_VERSION,
	ITEM_ID_VERSION_RESOURCE_FILE_VERSION
} VersionInfoItemIDs;

using versionInformationMap = std::map<VersionInfoItemIDs, std::wstring>;

class MetadataEx
{
public:
	bool getVersionInformation(
		const std::string& fileName,
		versionInformationMap& entity);

private:
	bool loadFile(
		const std::string& path,
		BYTE*& buffer,
		uint32_t& fileSize);

	bool openFile(
		const char* path, HANDLE& handle);

	bool mapFile(
		HANDLE handle,
		BYTE*& buf);

	void* displayErrorString(
		DWORD);

	bool searchVersionInfoByName(
		const version_values_t& versionInfo,
		const std::wstring& key,
		std::wstring& value);

};
