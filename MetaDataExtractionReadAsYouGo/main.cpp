#include "MetadataExtractionReadAsYouGo.h"
#include <iostream>

int main()
{
	versionInformationMap versionInfo;
	
	MetadataEx extractor("C:\\Windows\\system32\\hostname.exe");
	if (extractor.getVersionInformation(versionInfo))
	{
		auto originalFileName = versionInfo[ITEM_ID_VERSION_RESOURCE_ORIGINAL_FILE_NAME];
		auto companyName = versionInfo[ITEM_ID_VERSION_RESOURCE_COMPANY_NAME];
		auto productName = versionInfo[ITEM_ID_VERSION_RESOURCE_PRODUCT_NAME];
		auto productVersion = versionInfo[ITEM_ID_VERSION_RESOURCE_PRODUCT_VERSION];
		auto fileVersion = versionInfo[ITEM_ID_VERSION_RESOURCE_FILE_VERSION];
		auto subsystem = versionInfo[ITEM_ID_VERSION_RESOURCE_SUBSYSTEM];

		std::cout << std::endl;
		std::wcout << "Original Filename is [" << originalFileName << "].\n";
		std::wcout << "Company Name is      [" << companyName << "].\n";
		std::wcout << "Product Name is      [" << productName << "].\n";
		std::wcout << "Product Version is   [" << productVersion << "].\n";
		std::wcout << "File Version is      [" << fileVersion << "].\n";
		std::wcout << "SubSystem is         [" << subsystem << "].\n";
	}

	return 0;
}