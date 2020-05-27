//#include "pch.h"
#include "C:\Users\AMalik\source\repos\MetaDataExtractionReadAsYouGo\MetaDataExtractionReadAsYouGo\PEParser.h"
#include <cassert>

//namespace cu
//{
    void PEParser::reset()
    {
        m_fileName.clear();
        m_pDosHdr = NULL;
        m_pPeHdr = NULL;
        m_pNtHdr32 = NULL;
        m_pNtHdr64 = NULL;
        m_pFileHdr = NULL;
        m_pOptionalHdr32 = NULL;
        m_pOptionalHdr64 = NULL;
        m_pSectionTable = NULL;
        m_numDataDirectories = 0;
        m_numSections = 0;
        m_subSystem = 0;
        m_flags = PEfileType::PE_TYPE_NONE;
    }

    bool PEParser::parse(
		File& file)
     {
        auto ret { false };
        reset();

#if 0
		if (!fileName.size() || !pBuffer || !(*pBuffer) || bufSize <= 0)
		{
			throw std::runtime_error("Invalid arguments to parser.");
		}
#endif
		ret = file.seekStart(0);
        m_fileName = file.getName();
        
	    m_pDosHdr = new IMAGE_DOS_HEADER;
		ret = file.read(m_pDosHdr, sizeof(IMAGE_DOS_HEADER));

        // 'MZ' header check
        ret = ret && (m_pDosHdr->e_magic == IMAGE_DOS_SIGNATURE);
		if (ret)
		{
			m_pPeHdr = new IMAGE_NT_HEADERS;
			file.seekStart(m_pDosHdr->e_lfanew);

			file.read(m_pPeHdr, sizeof(IMAGE_NT_HEADERS));
			ret = (m_pPeHdr->Signature == IMAGE_NT_SIGNATURE);
			if (ret)
			{
				if (m_pPeHdr->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
				{
					std::cout << "32-bit" << std::endl;
					ret = parsePeFileType(PEfileType::PE_TYPE_32BIT, m_pNtHdr32, m_pOptionalHdr32);

				}
				else
				{
					std::cout << "64-bit" << std::endl;
					ret = parsePeFileType(PEfileType::PE_TYPE_64BIT, m_pNtHdr64, m_pOptionalHdr64);
				}

				auto offset = m_pDosHdr->e_lfanew +
					sizeof(m_pPeHdr->Signature) +
					sizeof(IMAGE_FILE_HEADER) +
					m_pPeHdr->FileHeader.SizeOfOptionalHeader;

				m_pSectionTable = new IMAGE_SECTION_HEADER[m_numSections];
				file.seekStart(offset);
				file.read(m_pSectionTable, sizeof(IMAGE_SECTION_HEADER) * m_numSections);
				for (auto i = 0u; i < m_numSections; i++)
				{
					std::cout << "Name is: " << m_pSectionTable[i].Name << std::endl;
				}
			}
			else
			{
				throw std::runtime_error(PE_PARSE_ERR "PE Signature not found.");
			}
		}
		else
		{
			std::cout << m_fileName << " is not a valid executable. Skipping." << std::endl;
		}

		if (!ret)
			reset();

		return ret;
	}

	template <typename T>
	bool constexpr validate_numeric_value(T value, T max, const T min = 0)
	{
		return (value > min && value < max);
	}

	template <typename T_IMAGE_NT_HEADER, typename T_IMAGE_OPTIONAL_HEADER>
	bool PEParser::parsePeFileType(
		const PEfileType PEfileTypeFlags,
		T_IMAGE_NT_HEADER& pNtHdr,
		T_IMAGE_OPTIONAL_HEADER& pOptionalHdr)
	{
		if (!m_pPeHdr)
		{
			throw std::runtime_error(PE_PARSE_ERR "PE header is not populated.");
		}

		m_flags = PEfileTypeFlags;
		m_pFileHdr = (IMAGE_FILE_HEADER*)(&(m_pPeHdr->FileHeader));
		pNtHdr = (T_IMAGE_NT_HEADER)m_pPeHdr;
		pOptionalHdr = (T_IMAGE_OPTIONAL_HEADER)(&(m_pPeHdr->OptionalHeader));

		if (!m_pFileHdr || !pOptionalHdr)
		{
			throw std::runtime_error(PE_PARSE_ERR "FileHeader and OptionalHeader are null.");
		}

		m_numSections = m_pFileHdr->NumberOfSections;
		m_subSystem = pOptionalHdr->Subsystem;
		m_numDataDirectories = pOptionalHdr->NumberOfRvaAndSizes;
		
		std::cout << "\nNumber of Sections = " << m_numSections << std::endl;
		std::cout << "Subsystem = " << m_subSystem << std::endl;
		std::cout << "NumDataDirectories = " << m_numDataDirectories << std::endl;

		auto ret{ validate_numeric_value(m_numSections, MAX_NUM_SECTIONS) };
		ret = ret && validate_numeric_value(m_subSystem, MAX_NUM_SUBSYSTEMS);
		ret = ret && validate_numeric_value(m_numDataDirectories, MAX_NUM_DATA_DIRECTORIES);

		return ret;
	}

    const uint32_t PEParser::getSubsystem() const
    {
        return m_subSystem;
    }

    bool PEParser::getResourceSection(
		resource_section_info_t& pResourceSection)
    {
        auto ret{ false };

		if (!m_pSectionTable || !m_numSections || (!m_pOptionalHdr64 && !m_pOptionalHdr32))
		{
			throw std::runtime_error("The PE is not yet parsed !");
		}

		std::cout << __LINE__ << std::endl;

        if (m_numDataDirectories > IMAGE_DIRECTORY_ENTRY_RESOURCE)
        {
            // This rva is only recommended to be used to locate the Section header for a section.
            // The exact offset (or rva) of the section is inside the section header of the section.
            auto rva{ 0ul };
			std::cout << __LINE__ << std::endl;
            if (m_flags == PEfileType::PE_TYPE_64BIT)
            {
                if (m_pOptionalHdr64)
                {
					std::cout << __LINE__ << std::endl;
                    rva = m_pOptionalHdr64->DataDirectory
                        [IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
                }
            }
            else
            {
				std::cout << __LINE__ << std::endl;
                if (m_pOptionalHdr32)
                {
					std::cout << __LINE__ << std::endl;
                    rva = m_pOptionalHdr32->DataDirectory
                        [IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
                }
            }

            ret = (rva > 0);
			std::cout << __LINE__ << "rva = " << rva << std::endl;
            if (ret)
            {
				std::cout << __LINE__ << std::endl;
                pResourceSection.hdr.sectionHdrIndex = -1;
				for (auto i{ 0u }; i < m_numSections; i++)
                {
                    auto sectionEnd = (m_pSectionTable[i].Misc.VirtualSize >
                            m_pSectionTable[i].SizeOfRawData) ?
                        m_pSectionTable[i].Misc.VirtualSize :
                        m_pSectionTable[i].SizeOfRawData;

					std::cout << __LINE__ << " and i = " << i << std::endl;
					auto offset = m_pSectionTable[i].PointerToRawData;
					std::cout << "offset[" << i << "] = " << offset << "\n";
					
                    if ((rva >= m_pSectionTable[i].VirtualAddress) &&
                            (rva < m_pSectionTable[i].VirtualAddress + sectionEnd))
                    {
                        strncpy_s(pResourceSection.hdr.name,
                                (char*)(m_pSectionTable[i].Name), IMAGE_SIZEOF_SHORT_NAME);
                        pResourceSection.hdr.name[IMAGE_SIZEOF_SHORT_NAME] = '\0';

                        pResourceSection.hdr.pSectionHdr = &m_pSectionTable[i];
						pResourceSection.datadirRva = rva;
                        pResourceSection.hdr.sectionHdrIndex = i;
                        pResourceSection.hdr.startRva = m_pSectionTable[i].VirtualAddress;
                        pResourceSection.hdr.endRva = m_pSectionTable[i].VirtualAddress + sectionEnd;

						std::cout << "Section header index for Resource section "
                            "is found at index [" << i << "] and name [" <<
                            pResourceSection.hdr.name << "].\n";
                        break;
                    }
                }

                if (pResourceSection.hdr.sectionHdrIndex == -1)
                {
                    std::cout << "Error: Resource section header not found.\n";
                    return false;
                }

                /* 
				Note:
                ====
				We have 2 ways to find the RVA of a particular section
				1) m_pOptionalHdrxx->DataDirectory[IMAGE_DIRECTORY_ENTRY_xxx].VirtualAddress;
				2) m_pSectionTable[sectionHdrIndex].VirtualAddress;

				The first RVA is only recommended to be used to locate the Section header for a section.
				Once the section header is found, the exact RVA of the section is inside that section header.
				
				Also note:
				Both these RVAs signify the offset (relative to the image base) of where the section will be
				loaded in the process Address space, when the loader will load the executable.
				*/
				ret = (pResourceSection.hdr.pSectionHdr != nullptr);
				std::cout << __LINE__ << std::endl;
                if (ret && pResourceSection.hdr.pSectionHdr->VirtualAddress !=
                        pResourceSection.datadirRva)
                {
					std::cout << __LINE__ << std::endl;
                    ret = false;
                    std::cout << "Resource section DataDirectory[RVA] = " <<
                        rva << " and SectionHdr[RVA] = " <<
                        pResourceSection.hdr.pSectionHdr->VirtualAddress <<
                        " are not same." << std::endl;
                    assert(1);
                }

				std::cout << __LINE__ << std::endl;
                if (ret)
                {
					std::cout << __LINE__ << std::endl;
                    pResourceSection.offset =
                        pResourceSection.hdr.pSectionHdr->PointerToRawData;

                    std::cout << "Resource Section offset  = " <<
                        pResourceSection.offset << std::endl;
                }
            }
        }

        return ret;
    }

#define SEEK_AND_READ(file,offset,buf,type,ret)\
do{\
    ret = file.seekStart(offset);\
    if (ret)\
    {\
        buf = new type;\
        ret = file.read(buf, sizeof(type));\
    }\
}while(0)

	template <typename T>
	bool seekAndRead (
		File& file,
		unsigned long offset,
		void** buf)
	{
		auto ret = file.seekStart(offset);
		*buf = new T;
		return file.read(*buf, sizeof(T));
	}

	static bool getResourceEntry(
		File& file,
		unsigned long offset,
		IMAGE_RESOURCE_DIRECTORY_ENTRY** entry)
	{
		bool ret;
		SEEK_AND_READ(file, offset, *entry, IMAGE_RESOURCE_DIRECTORY_ENTRY,ret);
		return ret;
		//auto ret = file.seekStart(offset);
		//*entry = new IMAGE_RESOURCE_DIRECTORY_ENTRY;
		//return file.read(*entry, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
	}

#if 0
	static bool getResourceDirectoryAndEntry(
		File& file,
		unsigned long& offset,
		IMAGE_RESOURCE_DIRECTORY** dir,
		IMAGE_RESOURCE_DIRECTORY_ENTRY** entry)
	{
		auto ret = file.seekStart(offset);
		*dir = new IMAGE_RESOURCE_DIRECTORY;
		ret = file.read(*dir, sizeof(IMAGE_RESOURCE_DIRECTORY));

		offset += sizeof(IMAGE_RESOURCE_DIRECTORY);
		ret = file.seekStart(offset);
		*entry = new IMAGE_RESOURCE_DIRECTORY_ENTRY;
		ret = file.read(*entry, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));

		return ret;
	}
#endif

	static bool getResourceDirectoryAndEntry(
		File& file,
		unsigned long& offset,
		IMAGE_RESOURCE_DIRECTORY** dir,
		IMAGE_RESOURCE_DIRECTORY_ENTRY** entry)
	{
		bool ret;
		SEEK_AND_READ(file, offset, *dir, IMAGE_RESOURCE_DIRECTORY, ret);

		if (ret)
		{
			offset += sizeof(IMAGE_RESOURCE_DIRECTORY);
			SEEK_AND_READ(file, offset,*entry, IMAGE_RESOURCE_DIRECTORY_ENTRY, ret);
		}
		return ret;
	}

	bool PEParser::parseResourceDir(
		const LPWSTR resourceId,
		resource_section_info_t& pResourceSection,
		File& file)
    {
        auto ret{ false };

		if (!resourceId)
		{
			throw std::runtime_error("Invalid arguments to parserResourceDir.");
		}

        if (getResourceSection(pResourceSection))
        {
            auto found{ false };

			if (!pResourceSection.hdr.pSectionHdr)
            {
                throw std::runtime_error(PE_PARSE_ERR "SectionHdr is null.");
            }

			// PointerToRawData: This is the file-based offset of where the resource section resides in PE.
			// VirtualAddress: This is the RVA to where the loader should map the section.
			auto seekOffset = pResourceSection.offset;
			auto rootDirOffset = pResourceSection.offset;

			SEEK_AND_READ(file, seekOffset, pResourceSection.levels[0].pDir, IMAGE_RESOURCE_DIRECTORY, ret);
			seekOffset += sizeof(IMAGE_RESOURCE_DIRECTORY);
			SEEK_AND_READ(file, seekOffset, pResourceSection.levels[0].pEntry, IMAGE_RESOURCE_DIRECTORY_ENTRY, ret);

#if 0
			std::cout << "Before seekOffset = " << seekOffset << std::endl;
			ret = getResourceDirectoryAndEntry(
				file,
				seekOffset,
				&pResourceSection.levels[0].pDir,
				&pResourceSection.levels[0].pEntry);
			std::cout << "After seekOffset = " << seekOffset << std::endl;
#endif
			if (!ret || !pResourceSection.levels[0].pDir || !pResourceSection.levels[0].pEntry)
            {
                throw std::runtime_error(PE_PARSE_ERR "ResourceDirectory is null.");
            }

			auto const pRootDir{ pResourceSection.levels[0].pDir };
            auto const pRootDirEntry{ pResourceSection.levels[0].pEntry };
            IMAGE_RESOURCE_DIRECTORY_ENTRY* pTempDirEntry{ pRootDirEntry };

            // Locate required id type directory entry in root dir
            ret = pRootDir && pRootDirEntry;
            if (ret)
            {
                for (auto i = 0;
					i < (pRootDir->NumberOfIdEntries +
						pRootDir->NumberOfNamedEntries);
					i++)
                {
					std::cout << "Id is : " << pTempDirEntry->Id << " and resourceId = " << (short)resourceId << std::endl;
                    if (pTempDirEntry &&
                            pTempDirEntry->DataIsDirectory &&
                            pTempDirEntry->Id == (short)resourceId)
                    {
						std::cout << "0Found at index = " << i << std::endl;
                        found = true;
                        break;
                    }

					seekOffset += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
					//file.seekStart(seekOffset);
					//pTempDirEntry = new IMAGE_RESOURCE_DIRECTORY_ENTRY;
					//file.read(pTempDirEntry, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
					//auto nextEntryOffset = rootDirOffset + (i+1)*(sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
					//getResourceEntry(file, seekOffset, &pTempDirEntry);
					SEEK_AND_READ(file, seekOffset, pTempDirEntry, IMAGE_RESOURCE_DIRECTORY_ENTRY, ret);

					std::cout << "Id is : " << pTempDirEntry->Id << " and resourceId = " << (short)resourceId << std::endl;
					std::cout << "OffsetToDirectory = " << pTempDirEntry->OffsetToDirectory << std::endl;
					std::cout << "seekOffset = " << seekOffset << std::endl;
					std::cout << "sizeof(IMAGE_RESOURCE_DIRECTORY) = " << sizeof(IMAGE_RESOURCE_DIRECTORY) << std::endl;
					std::cout << "sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) = " << sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) << std::endl;
                }
            }

			

            if (!found)
            {
                std::cout << "Info: Resource " << (short)resourceId << " not found in the EXE.\n";
                ret = false;
            }

			//return found;
			if (found)
			{
				// Level 1
				auto nextDirOffset = rootDirOffset + pTempDirEntry->OffsetToDirectory;
				SEEK_AND_READ(file, nextDirOffset, pResourceSection.levels[1].pDir, IMAGE_RESOURCE_DIRECTORY, ret);
				nextDirOffset += sizeof(IMAGE_RESOURCE_DIRECTORY);
				SEEK_AND_READ(file, nextDirOffset, pResourceSection.levels[1].pEntry, IMAGE_RESOURCE_DIRECTORY_ENTRY, ret);
#if 0
				ret = getResourceDirectoryAndEntry(
					file,
					nextDirOffset,
					&pResourceSection.levels[1].pDir,
					&pResourceSection.levels[1].pEntry);
#endif
				if (!ret)
				{
					throw std::runtime_error(PE_PARSE_ERR "ResourceDirectory is null.");
				}

				std::cout << "For level 2: NumIds + NumNames = " <<
					pResourceSection.levels[1].pDir->NumberOfIdEntries +
					pResourceSection.levels[1].pDir->NumberOfNamedEntries << std::endl;

				pTempDirEntry = pResourceSection.levels[1].pEntry;
				for (auto i{ 0 };
					i < (pResourceSection.levels[1].pDir->NumberOfIdEntries +
						pResourceSection.levels[1].pDir->NumberOfNamedEntries);
					i++)
				{
					// Level 2
					assert(pTempDirEntry->DataIsDirectory == 1); // level 2 points to DataDirectory
					if (pTempDirEntry && pTempDirEntry->DataIsDirectory == 1)
					{
						auto nextDirOffset = rootDirOffset + pTempDirEntry->OffsetToDirectory;
						SEEK_AND_READ(file, nextDirOffset, pResourceSection.levels[2].pDir, IMAGE_RESOURCE_DIRECTORY, ret);
						nextDirOffset += sizeof(IMAGE_RESOURCE_DIRECTORY);
						SEEK_AND_READ(file, nextDirOffset, pResourceSection.levels[2].pEntry, IMAGE_RESOURCE_DIRECTORY_ENTRY, ret);

#if 0
						ret = getResourceDirectoryAndEntry(file,
							seekOffset,
							&pResourceSection.levels[2].pDir,
							&pResourceSection.levels[2].pEntry);
#endif
						if (!ret)
						{
							throw std::runtime_error(PE_PARSE_ERR "ResourceDirectory is null.");
						}

						std::cout << "For level 3: NumIds + NumNames = " <<
							pResourceSection.levels[2].pDir->NumberOfIdEntries +
							pResourceSection.levels[2].pDir->NumberOfNamedEntries << std::endl;

						pTempDirEntry = pResourceSection.levels[2].pEntry;
						for (i = 0;
							i < (pResourceSection.levels[2].pDir->NumberOfIdEntries +
								pResourceSection.levels[2].pDir->NumberOfNamedEntries);
							i++)
						{
							// Level 3
							assert(pTempDirEntry->DataIsDirectory == 0); // level 3 points to Data (leaf node)
							SEEK_AND_READ(file, rootDirOffset + pTempDirEntry->OffsetToData, pResourceSection.pData, IMAGE_RESOURCE_DATA_ENTRY, ret);
							//pResourceSection.pData = (IMAGE_RESOURCE_DATA_ENTRY*)
								//((BYTE*)pRootDir + pTempDirEntry->OffsetToData);
							
							if (pResourceSection.pData)
							{
								// Size of data must be non-zero
								assert(pResourceSection.pData->Size > 0);

								auto dataOffset{ pResourceSection.pData->OffsetToData - pResourceSection.datadirRva };
								ret = file.seekStart(rootDirOffset + dataOffset);
								if (ret)
								{
									pResourceSection.pDataBuffer = new BYTE[pResourceSection.pData->Size];
									ret = file.read(pResourceSection.pDataBuffer, sizeof(BYTE) * pResourceSection.pData->Size);
								}
								//SEEK_AND_READ(file, rootDirOffset + dataOffset, pResourceSection.pDataBuffer, BYTE, ret);
								//pResourceSection.pDataBuffer = (BYTE*)pRootDir + dataOffset;
								
								//ret = true;
							}
						}
					}
				}
			}
        }

        return ret;
    }

    bool PEParser::parseVersionInfo(
		const resource_section_info_t& pResourceSection,
		version_values_t& vi)
    {
		auto found{ false };
		if (vi.empty())
		{
			if (!pResourceSection.pDataBuffer || !pResourceSection.pData)
			{
				throw std::runtime_error(VERINFO_PARSE_ERR "ResourceDirectory is not already populated.");
			}

			auto versionInfoSize{ pResourceSection.pData->Size };
			auto pVersionInfo{ (version_info_t*)(pResourceSection.pDataBuffer) };
			auto ret = pVersionInfo && pVersionInfo->key && pVersionInfo->key[0];
			if (!ret)
			{
				throw std::runtime_error(VERINFO_PARSE_ERR "VersionInfo key is Null or empty.");
			}

			ret = (wcsncmp(pVersionInfo->key, VS_VERSION_STRING, VS_VERSION_STRING_LEN) == 0);
			if (!ret)
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
			ret = pFileInfo && pFileInfo->key && pFileInfo->key[0];
			if (!ret)
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
					offset += (unsigned long)(wcslen(key) * sizeof(wchar_t) + sizeof(wchar_t));
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
