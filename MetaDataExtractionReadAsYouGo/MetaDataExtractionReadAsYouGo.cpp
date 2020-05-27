// MetadataExtractorC++.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "MetadataExtractionReadAsYouGo.h"


/********************* MetadataEx ******************/
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

		ret = m_file.open();
		CHECK_RET_CODE(ret, "loadFile failed");

		ret = ret && parser.parse(m_file);
		CHECK_RET_CODE(ret, "parsing PE header failed");

		ret = ret && parser.parseResourceDir(RT_VERSION, resourceSectionInfo, m_file);
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
