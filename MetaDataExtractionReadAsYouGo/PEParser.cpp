//#include "pch.h"
#include "PEParser.h"
#include <cassert>

//namespace cu
//{
	PEParser::PEParser()
	{
		<-- You can do this inline where these variables are declared. That is the recommended approach
		m_fileName.clear();
		m_spDosHdr = NULL;
		m_spPeHdr = NULL;
		m_pNtHdr32 = NULL;
		m_pNtHdr64 = NULL;
		m_pFileHdr = NULL;
		m_pOptionalHdr32 = NULL;
		m_pOptionalHdr64 = NULL;
		m_spSectionTable = NULL;
		m_numDataDirectories = 0;
		m_numSections = 0;
		m_subSystem = 0;
		m_bufSize = 0;
		m_flags = PEfileType::PE_TYPE_NONE;
	}

	<-- Can we specify seek and reading function once in constructor? 
		Will you ever need separate functions for different calls to parse?
	bool PEParser::parse(
		const std::string& fileName,
		std::function<bool(long)> pSeek,
		std::function<bool(void*, const DWORD)> pRead)
     {
		if (!fileName.size() || !pSeek || !pRead)
		{
			throw std::runtime_error("Invalid arguments to parser.");
		}

		auto success{ false };
		auto currentOffset{ 0u };

		m_fileName = fileName;
		m_pSeek = pSeek;
		m_pRead = pRead;

		SEEK_AND_READ(currentOffset, m_spDosHdr, IMAGE_DOS_HEADER, 1, success);

		// 'MZ' header check
		success = success && (m_spDosHdr.get()->e_magic == IMAGE_DOS_SIGNATURE);
		if (success)
		{
			currentOffset += m_spDosHdr.get()->e_lfanew;
			SEEK_AND_READ(currentOffset, m_spPeHdr, IMAGE_NT_HEADERS, 1, success);
			success = (m_spPeHdr.get()->Signature == IMAGE_NT_SIGNATURE);
		}
		else
		{
			std::cout << m_fileName << " is not a valid executable. Skipping." << std::endl;
		}

		if (success)
		{
			if (m_spPeHdr.get()->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
			{
				success = parsePeFileType(PEfileType::PE_TYPE_32BIT, m_pNtHdr32, m_pOptionalHdr32);
			}
			else
			{
				success = parsePeFileType(PEfileType::PE_TYPE_64BIT, m_pNtHdr64, m_pOptionalHdr64);
			}

			currentOffset += sizeof(m_spPeHdr.get()->Signature) + sizeof(IMAGE_FILE_HEADER) +
				m_spPeHdr.get()->FileHeader.SizeOfOptionalHeader;
			SEEK_AND_READ(currentOffset, m_spSectionTable, IMAGE_SECTION_HEADER, m_numSections, success);
		}
		else
		{
			throw std::runtime_error(PE_PARSE_ERR "PE Signature not found.");
		}

		return success;
	}

	template <typename T>
	static bool constexpr validate_numeric_value(T value, const T max, const T min = 0)
	{
		return (value > min && value < max);
	}

	template <typename T_IMAGE_NT_HEADER, typename T_IMAGE_OPTIONAL_HEADER>
	bool PEParser::parsePeFileType(
		const PEfileType PEfileTypeFlags,
		T_IMAGE_NT_HEADER& pNtHdr,
		T_IMAGE_OPTIONAL_HEADER& pOptionalHdr)
	{
		if (!m_spPeHdr)
		{
			throw std::runtime_error(PE_PARSE_ERR "PE header is not populated.");
		}

		m_flags = PEfileTypeFlags;
		m_pFileHdr = (IMAGE_FILE_HEADER*)(&(m_spPeHdr.get()->FileHeader));
		pNtHdr = (T_IMAGE_NT_HEADER)m_spPeHdr.get();
		pOptionalHdr = (T_IMAGE_OPTIONAL_HEADER)(&(m_spPeHdr.get()->OptionalHeader));

		if (!m_pFileHdr || !pOptionalHdr)
		{
			throw std::runtime_error(PE_PARSE_ERR "FileHeader and OptionalHeader are null.");
		}

		m_numSections = m_pFileHdr->NumberOfSections;
		m_subSystem = pOptionalHdr->Subsystem;
		m_numDataDirectories = pOptionalHdr->NumberOfRvaAndSizes;

		std::cout << "Subsystem = " << m_subSystem << std::endl;
		std::cout << "Number of Sections = " << m_numSections << std::endl;
		std::cout << "NumDataDirectories = " << m_numDataDirectories << std::endl;

		auto success{ validate_numeric_value(m_numSections, MAX_NUM_SECTIONS) };
		success = success && validate_numeric_value(m_subSystem, MAX_NUM_SUBSYSTEMS);
		success = success && validate_numeric_value(m_numDataDirectories, MAX_NUM_DATA_DIRECTORIES);

		return success;
	}

	const uint32_t PEParser::getSubsystem() const
    {
        return m_subSystem;
    }

	bool PEParser::getResourceSection(
		resource_section_info_t& pResourceSection)
	{
		auto success{ false };

		if (!m_spSectionTable || !m_numSections || (!m_pOptionalHdr64 && !m_pOptionalHdr32))
		{
			throw std::runtime_error("The PE is not yet parsed !");
		}

		if (m_numDataDirectories > IMAGE_DIRECTORY_ENTRY_RESOURCE)
		{
			auto rva{ 0ul };
			if (m_pOptionalHdr64)
			{
				assert(m_flags == PEfileType::PE_TYPE_64BIT);
				rva = m_pOptionalHdr64->DataDirectory
					[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
			}
			else
			{
				assert(m_flags == PEfileType::PE_TYPE_32BIT);
				rva = m_pOptionalHdr32->DataDirectory
					[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
			}

			for (auto i{ 0u }; i < m_numSections; i++)
			{
				auto pSectionTable = m_spSectionTable.get();
				auto sectionEnd = (pSectionTable[i].Misc.VirtualSize >
					pSectionTable[i].SizeOfRawData) ?
					pSectionTable[i].Misc.VirtualSize :
					pSectionTable[i].SizeOfRawData;

				if ((rva >= pSectionTable[i].VirtualAddress) &&
					(rva < pSectionTable[i].VirtualAddress + sectionEnd))
				{
#ifdef _DEBUG
					char sectionName[IMAGE_SIZEOF_SHORT_NAME + 1];
					strncpy_s(sectionName,
						(char*)(pSectionTable[i].Name), IMAGE_SIZEOF_SHORT_NAME);
					sectionName[IMAGE_SIZEOF_SHORT_NAME] = '\0';
					std::cout << "SectionName = " << sectionName << std::endl;
#endif
					assert(rva == pSectionTable[i].VirtualAddress);
					pResourceSection.datadirRva = rva;
					pResourceSection.offset = pSectionTable[i].PointerToRawData;
					return true;
				}
			}

			std::cout << "Error: Resource section header not found.\n";
		}

		return success;
	}

	bool PEParser::parseResourceDir(
		const LPWSTR resourceId,
		resource_section_info_t& pResourceSection)
	{
		auto success{ false };

		if (!resourceId)
		{
			throw std::runtime_error("Invalid arguments to parserResourceDir.");
		}

		if (this->getResourceSection(pResourceSection))
		{
			// PointerToRawData: This is the file-based offset of where the resource section resides in PE.
			// VirtualAddress: This is the RVA to where the loader should map the section.
			auto seekOffset = pResourceSection.offset;
			auto rootDirOffset = pResourceSection.offset;

			SEEK_AND_READ(seekOffset, pResourceSection.levels[0].spDir, IMAGE_RESOURCE_DIRECTORY, 1, success);
			seekOffset += sizeof(IMAGE_RESOURCE_DIRECTORY);
			SEEK_AND_READ_SHARED(seekOffset, pResourceSection.levels[0].spEntry, IMAGE_RESOURCE_DIRECTORY_ENTRY, 1, success);

			if (!success || !pResourceSection.levels[0].spDir || !pResourceSection.levels[0].spEntry)
			{
				throw std::runtime_error(PE_PARSE_ERR "ResourceDirectory is null.");
			}

			// Locate required id type directory entry in root dir
			auto pTempDirEntry{ pResourceSection.levels[0].spEntry };
			auto found{ false };
			for (auto i = 0;
				i < (pResourceSection.levels[0].spDir.get()->NumberOfIdEntries +
					pResourceSection.levels[0].spDir.get()->NumberOfNamedEntries);
				i++)
			{
				if (pTempDirEntry &&
					pTempDirEntry.get()->DataIsDirectory &&
					pTempDirEntry.get()->Id == (WORD)((ULONG_PTR)resourceId))
				{
					found = true;
					break;
				}

				seekOffset += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
				SEEK_AND_READ_SHARED(seekOffset, pTempDirEntry, IMAGE_RESOURCE_DIRECTORY_ENTRY, 1, success);
			}

			if (!found)
			{
				std::cout << "Info: Resource " << resourceId << " not found in the EXE.\n";
				success = false;
			}
			else
			{
				// Level 1
				auto nextDirOffset = rootDirOffset + pTempDirEntry.get()->OffsetToDirectory;
				SEEK_AND_READ(nextDirOffset, pResourceSection.levels[1].spDir, IMAGE_RESOURCE_DIRECTORY, 1, success);

				if (success)
				{
					nextDirOffset += sizeof(IMAGE_RESOURCE_DIRECTORY);
					SEEK_AND_READ_SHARED(nextDirOffset, pResourceSection.levels[1].spEntry,
						IMAGE_RESOURCE_DIRECTORY_ENTRY, 1, success);
				}

				if (!success)
				{
					throw std::runtime_error(PE_PARSE_ERR "ResourceDirectory is null.");
				}

				pTempDirEntry = pResourceSection.levels[1].spEntry;
				for (auto i{ 0 };
					i < (pResourceSection.levels[1].spDir.get()->NumberOfIdEntries +
						pResourceSection.levels[1].spDir.get()->NumberOfNamedEntries);
					i++)
				{
					// Level 2
					assert(pTempDirEntry.get()->DataIsDirectory == 1); // level 2 points to DataDirectory
					if (pTempDirEntry && pTempDirEntry.get()->DataIsDirectory == 1)
					{
						nextDirOffset = rootDirOffset + pTempDirEntry.get()->OffsetToDirectory;
						SEEK_AND_READ(nextDirOffset, pResourceSection.levels[2].spDir,
							IMAGE_RESOURCE_DIRECTORY, 1, success);

						if (success)
						{
							nextDirOffset += sizeof(IMAGE_RESOURCE_DIRECTORY);
							SEEK_AND_READ_SHARED(nextDirOffset, pResourceSection.levels[2].spEntry,
								IMAGE_RESOURCE_DIRECTORY_ENTRY, 1, success);
						}

						if (!success)
						{
							throw std::runtime_error(PE_PARSE_ERR "ResourceDirectory is null.");
						}

						pTempDirEntry = pResourceSection.levels[2].spEntry;
						for (i = 0;
							i < (pResourceSection.levels[2].spDir.get()->NumberOfIdEntries +
								pResourceSection.levels[2].spDir.get()->NumberOfNamedEntries);
							i++)
						{
							// Level 3
							std::cout << "Level 3 -->\n";
							std::cout << "Num Ids = " << pResourceSection.levels[2].spDir.get()->NumberOfIdEntries << std::endl;
							std::cout << "Num Named = " << pResourceSection.levels[2].spDir.get()->NumberOfNamedEntries << std::endl;
														
							std::unique_ptr<IMAGE_RESOURCE_DATA_ENTRY[]> spData;
							assert(pTempDirEntry.get()->DataIsDirectory == 0); // level 3 points to Data (leaf node)

							SEEK_AND_READ(rootDirOffset + (ULONG)(pTempDirEntry.get()->OffsetToData), spData,
								IMAGE_RESOURCE_DATA_ENTRY, 1, success);

							if (spData)
							{
								// Size of data must be non-zero
								pResourceSection.dataBufferSize = spData.get()->Size;
								assert(pResourceSection.dataBufferSize > 0);

								auto dataOffset{ spData.get()->OffsetToData - pResourceSection.datadirRva };
								SEEK_AND_READ(rootDirOffset + dataOffset, pResourceSection.spDataBuffer,
									BYTE, pResourceSection.dataBufferSize, success);
								break;
							}
						}

						if (!pResourceSection.spDataBuffer)
						{
							std::cout << "Unable to extract data for resource Id [" << resourceId << "]\n";
						}
					}
				}
			}
		}

		return success;
	}

    bool PEParser::parseVersionInfo(
		const resource_section_info_t& pResourceSection,
		version_values_t& vi)
    {
		auto found{ false };
		if (vi.empty())
		{
			if (!pResourceSection.spDataBuffer || !pResourceSection.dataBufferSize)
			{
				throw std::runtime_error(VERINFO_PARSE_ERR "ResourceDirectory is not already populated.");
			}

			auto versionInfoSize{ pResourceSection.dataBufferSize };
			auto pVersionInfo{ (version_info_t*)(pResourceSection.spDataBuffer.get()) };
			auto success = pVersionInfo && pVersionInfo->key && pVersionInfo->key[0];
			if (!success)
			{
				throw std::runtime_error(VERINFO_PARSE_ERR "VersionInfo key is Null or empty.");
			}

			success = (wcsncmp(pVersionInfo->key, VS_VERSION_STRING, VS_VERSION_STRING_LEN) == 0);
			if (!success)
			{
				throw std::runtime_error(VERINFO_PARSE_ERR "VersionInfo key has unexpected value.");
			}

			/* Align it to 32 bit boundry */
			auto offset = offsetof(version_info_t, opaque);
			ALIGN_32BIT_BOUNDRY(offset);
			offset += pVersionInfo->val_length;
			ALIGN_32BIT_BOUNDRY(offset);

			auto tmp = (BYTE*)pVersionInfo + offset;
			auto pFileInfo = (string_file_info_t*)tmp;

        repeat:
			success = pFileInfo && pFileInfo->key && pFileInfo->key[0];
			if (!success)
			{
				throw std::runtime_error(VERINFO_PARSE_ERR "FileInfo key is Null or empty.");
			}

			if (pFileInfo->length > (sizeof(version_info_t) +
				(size_t)(tmp - pVersionInfo->opaque)))
			{
				throw std::runtime_error(VERINFO_PARSE_ERR "FileInfo length is too large.");
			}

			if (pFileInfo->length < sizeof(string_file_info_t))
			{
				throw std::runtime_error(VERINFO_PARSE_ERR "FileInfo length is too small.");
			}

			if (wcsncmp(pFileInfo->key, FILE_INFO_STRING, FILE_INFO_STRING_LEN) != 0)
			{
				if ((wcsncmp(pFileInfo->key, VAR_FILE_INFO_STRING, VAR_FILE_INFO_STRING_LEN) == 0) &&
					(pFileInfo->length < versionInfoSize))
				{
					offset = pFileInfo->length;
					ALIGN_32BIT_BOUNDRY(offset);
					pFileInfo = (string_file_info_t*)((BYTE*)pFileInfo + offset);
					goto repeat;
				}
				else
				{
					throw std::runtime_error(VERINFO_PARSE_ERR "Unexpected FileInfo key encountered.");
				}
			}

			auto currentSize = offsetof(string_file_info_t, opaque);
			ALIGN_32BIT_BOUNDRY(currentSize);
			while (currentSize < pFileInfo->length)
			{
				auto pTable = (string_tbl_t*)((BYTE*)pFileInfo + currentSize);

				currentSize += pTable->length;
				ALIGN_32BIT_BOUNDRY(currentSize);
				if (pTable->length < sizeof(string_tbl_t))
				{
					throw std::runtime_error(VERINFO_PARSE_ERR "String Table length is too small.");
				}

				if (versionInfoSize < (ULONG)(((BYTE*)pTable - (BYTE*)pVersionInfo) +
					pTable->length))
				{
					throw std::runtime_error(VERINFO_PARSE_ERR "String Table length is too large.");
				}

				if (NULL == pTable->key + 2)
				{
					throw std::runtime_error(VERINFO_PARSE_ERR "String Table key is not valid.");
				}

				/* We are interested only in english language version info */
				if (wcsncmp(pTable->key + 2, ENG_LANG_CODE_STRING, 2) != 0)
				{
					/* Hack for some bad behaving apps */
					if (wcsncmp(pTable->key + 2, (L"00"), 2) != 0)
						continue;
				}

				auto currentStringTableSize = offsetof(string_tbl_t, opaque);
				ALIGN_32BIT_BOUNDRY(currentStringTableSize);
				while (currentStringTableSize < pTable->length)
				{
					auto pString = (string_t*)((BYTE*)pTable + currentStringTableSize);
					if (pString->length < sizeof(string_t))
					{
						throw std::runtime_error(VERINFO_PARSE_ERR "String Table length is not valid.");
					}

					if (versionInfoSize < (ULONG)(((BYTE*)pString - (BYTE*)pVersionInfo) +
						pString->length))
					{
						throw std::runtime_error(VERINFO_PARSE_ERR "String Table length is not large.");
					}

					currentStringTableSize += pString->length;
					ALIGN_32BIT_BOUNDRY(currentStringTableSize);

					if (pString->type == 0)
					{
						continue;
					}

					auto key = (wchar_t*)pString->opaque;
					offset = offsetof(string_t, opaque);
					offset += (ULONG)(wcslen(key) * sizeof(wchar_t) + sizeof(wchar_t));
					ALIGN_32BIT_BOUNDRY(offset);
					auto value = (wchar_t*)((BYTE*)pString + offset);

					vi.emplace_back(std::make_pair(std::wstring(key), std::wstring(value)));
					found = true;
				}
			}
		}
		else
		{
			found = true;
		}

        return found;
    }
	
#ifdef _DEBUG
	const char* getNameFromId(int Id)
	{
		static const char* ResourceTypes[] = {
			"0",
			"CURSOR",
			"BITMAP",
			"ICON",
			"MENU",
			"DIALOG",
			"STRING",
			"FONTDIR",
			"FONT",
			"ACCELERATORS",
			"RCDATA",
			"MESSAGETABLE",
			"GROUP_CURSOR",
			"13",
			"GROUP_ICON",
			"15",
			"VERSION",
			"DLGINCLUDE",
			"18",
			"PLUGPLAY",
			"VXD",
			"ANICURSOR",
			"ANIICON",
			"HTML",
			"MANIFEST"
		};

		if (Id > 24)
			return nullptr;
		return ResourceTypes[Id];
	}
#endif
//}
