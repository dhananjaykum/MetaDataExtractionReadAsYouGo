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
	auto found{ false }; <-- bool should be fine here. No advantage of using auto
	for (auto i : versionInfo) <-- const auto& i (otherwise copy i created)
	{
		<-- You can use more meaningful names instead of first and second.
		const auto& [meaningfulNameInsteadofFirst, meaningfulNameInsteadOfSecond] (Check structured bindings)
		if (wcsncmp(i.first.c_str(), key.c_str(), key.size()) == 0)
		{
			value = i.second;
			found = true;
		}
	}

	<-- Can we just return empty string in case of not found? Change the signature to return string?
	if (!found)
	{
		std::wcout << "Resource value " << key << " not found in VS_VERSIONINFO.\n";
	}
	return found;
}

bool MetadataEx::getVersionInformation(
	versionInformationMap& entity)
{
	version_values_t versionInfo;
	uint32_t subsystem;
	auto ret{ false };

	try
	{
		resource_section_info_t resourceSectionInfo{};
		PEParser parser;

		ret = m_file.open();
		CHECK_RET_CODE(ret, "openFile failed");
		
		ret = ret && parser.parse(m_file.getName(),
			std::bind(&File::seekStart, &m_file, std::placeholders::_1),
			std::bind(&File::read, &m_file, std::placeholders::_1, std::placeholders::_2));
		CHECK_RET_CODE(ret, "parsing PE header failed");

		ret = ret && parser.parseResourceDir(RT_VERSION, resourceSectionInfo);
		CHECK_RET_CODE(ret, "parseResourceDir failed");

		ret = ret && parser.parseVersionInfo(resourceSectionInfo, versionInfo);
		CHECK_RET_CODE(ret, "parseVersionInfo failed");

		subsystem = parser.getSubsystem();
	}

	catch (const std::exception & ex)
	{
		std::cout << "Caught exception: " << ex.what() << std::endl;
		return false;
	}

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

		entity.emplace(ITEM_ID_VERSION_RESOURCE_SUBSYSTEM, std::to_wstring(subsystem));
	}
out: <-- No need for out:
	return ret;
}
