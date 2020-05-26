//#include "pch.h"
#include "c:\\Users\AMalik\source\repos\MetadataExtractorC++\MetadataExtractorC++\PEParser.h"
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
            const std::string& fileName,
            const BYTE* pBuffer,
            const uint32_t bufSize)
    {
        auto ret { false };
        reset();

		if (!fileName.size() || !pBuffer || !(*pBuffer) || bufSize <= 0)
		{
			throw std::runtime_error("Invalid arguments to parser.");
		}

        m_fileName = fileName;
        m_bufSize = bufSize;
        m_pDosHdr = (IMAGE_DOS_HEADER*)(pBuffer);

        // 'MZ' header check
        ret = (m_pDosHdr != nullptr) &&
           (m_bufSize > sizeof(IMAGE_DOS_HEADER)) &&
           (m_pDosHdr->e_magic == IMAGE_DOS_SIGNATURE);

        if (ret)
        {
            // Boundry check
            ret = (m_bufSize > (uint32_t) m_pDosHdr->e_lfanew) &&
                (m_bufSize > (uint32_t)(m_pDosHdr->e_lfanew + sizeof(IMAGE_NT_HEADERS32)));
            if (ret)
            {
                // PE signature check
                m_pPeHdr = (IMAGE_NT_HEADERS*)((BYTE*)m_pDosHdr + m_pDosHdr->e_lfanew);
                ret = (m_pPeHdr != nullptr) && (m_pPeHdr->Signature == IMAGE_NT_SIGNATURE);

                if (ret)
                {
                    // 32-bit or 64-bit?
                    if (m_pPeHdr->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
                    {
                        ret = parsePeFileType(PEfileType::PE_TYPE_32BIT, m_pNtHdr32, m_pOptionalHdr32);
                    }
                    else if (m_pPeHdr->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                    {
                        ret = parsePeFileType(PEfileType::PE_TYPE_64BIT, m_pNtHdr64, m_pOptionalHdr64);
                    }
				}
                else
                {
                    throw std::runtime_error (PE_PARSE_ERR "PE Signature not found.");
                }
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
		m_pSectionTable = (IMAGE_SECTION_HEADER*)((BYTE*)(pOptionalHdr)+m_pFileHdr->SizeOfOptionalHeader);

		std::cout << "\nNumber of Sections = " << m_numSections << std::endl;
		std::cout << "m_pDosHdr = " << m_pDosHdr << ", and m_pSectionTable = " << m_pSectionTable << std::endl;
		std::cout << "m_pSectionTable offset is " << (BYTE*)m_pSectionTable - (BYTE*)m_pDosHdr << std::endl;
		std::cout << "m_pFileHdr offset is " << (BYTE*)m_pFileHdr - (BYTE*)m_pDosHdr << std::endl;
		std::cout << "pOptionalHdr offset is " << (BYTE*)pOptionalHdr - (BYTE*)m_pDosHdr << std::endl;
		return (m_pSectionTable != NULL);
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

        if (m_numDataDirectories > IMAGE_DIRECTORY_ENTRY_RESOURCE)
        {
            // This rva is only recommended to be used to locate the Section header for a section.
            // The exact offset (or rva) of the section is inside the section header of the section.
            auto rva{ 0ul };

            if (m_flags == PEfileType::PE_TYPE_64BIT)
            {
                if (m_pOptionalHdr64)
                {
                    rva = m_pOptionalHdr64->DataDirectory
                        [IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
                }
            }
            else
            {
                if (m_pOptionalHdr32)
                {
                    rva = m_pOptionalHdr32->DataDirectory
                        [IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
                }
            }

            ret = (rva > 0);
            if (ret)
            {
                pResourceSection.hdr.sectionHdrIndex = -1;
				for (auto i{ 0u }; i < m_numSections; i++)
                {
                    auto sectionEnd = (m_pSectionTable[i].Misc.VirtualSize >
                            m_pSectionTable[i].SizeOfRawData) ?
                        m_pSectionTable[i].Misc.VirtualSize :
                        m_pSectionTable[i].SizeOfRawData;

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
                if (ret && pResourceSection.hdr.pSectionHdr->VirtualAddress !=
                        pResourceSection.datadirRva)
                {
                    ret = false;
                    std::cout << "Resource section DataDirectory[RVA] = " <<
                        rva << " and SectionHdr[RVA] = " <<
                        pResourceSection.hdr.pSectionHdr->VirtualAddress <<
                        " are not same." << std::endl;
                    assert(1);
                }

                ret = ret && (m_bufSize > pResourceSection.hdr.pSectionHdr->PointerToRawData +
                        pResourceSection.hdr.pSectionHdr->SizeOfRawData);
                if (ret)
                {
                    pResourceSection.offset =
                        pResourceSection.hdr.pSectionHdr->PointerToRawData;

                    std::cout << "Resource Section offset  = " <<
                        pResourceSection.offset << std::endl;
                }
            }
        }

        return ret;
    }

	static bool getResourceDirectoryAndEntry(
		BYTE* base,
		unsigned long offset,
		IMAGE_RESOURCE_DIRECTORY** dir,
		IMAGE_RESOURCE_DIRECTORY_ENTRY** entry)
	{
		if (!dir)
		{
			throw std::runtime_error("Invalid arguments to getResourceDirectoryAndEntry");
		}

		auto ret{ false };
		if (dir)
		{
			*dir = (IMAGE_RESOURCE_DIRECTORY*)(base + offset);
			if (*dir)
			{
				if (entry)
				{
					*entry = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)
						((BYTE*)* dir + sizeof(IMAGE_RESOURCE_DIRECTORY));

					if (*entry)
					{
						ret = true;
					}
				}
				else
				{
					ret = true;
				}
			}
		}
		return ret;
	}
	bool PEParser::parseResourceDir(
		const LPWSTR resourceId,
		resource_section_info_t& pResourceSection)
    {
        auto ret{ false };

		if (!resourceId)
		{
			throw std::runtime_error("Invalid arguments to parserResourceDir.");
		}

        if (getResourceSection(pResourceSection))
        {
            auto found{ false };

            ret = m_pDosHdr && pResourceSection.hdr.pSectionHdr &&
                (m_bufSize > pResourceSection.hdr.pSectionHdr->PointerToRawData);

            if (!ret)
            {
                throw std::runtime_error(PE_PARSE_ERR "SectionHdr is null.");
            }

            // PointerToRawData: This is the file-based offset of where the resource section resides in PE.
            // VirtualAddress: This is the RVA to where the loader should map the section.
            ret = ret && getResourceDirectoryAndEntry((BYTE*)m_pDosHdr,
                    pResourceSection.hdr.pSectionHdr->PointerToRawData,
                    &pResourceSection.levels[0].pDir,
                    &pResourceSection.levels[0].pEntry);

            if (!ret)
            {
                throw std::runtime_error(PE_PARSE_ERR "ResourceDirectory is null.");
            }

            auto const pRootDir{ pResourceSection.levels[0].pDir };
            auto const pRootDirEntry{ pResourceSection.levels[0].pEntry };
            auto pTempDirEntry{ pRootDirEntry };

            // Locate required id type directory entry in root dir
            ret = pRootDir && pRootDirEntry;
            if (ret)
            {
                for (auto i{ 0 };
                        i < (pRootDir->NumberOfIdEntries + pRootDir->NumberOfNamedEntries);
                        i++, pTempDirEntry++)
                {
                    if (pTempDirEntry &&
                            pTempDirEntry->DataIsDirectory &&
                            pTempDirEntry->Id == (size_t)resourceId)
                    {
                        found = true;
                        break;
                    }
                }
            }

            if (!found)
            {
                std::cout << "Info: Resource " << resourceId << " not found in the EXE.\n";
                ret = false;
            }

            if (found)
            {
                // Level 1
                ret = getResourceDirectoryAndEntry(
                        (BYTE*)pRootDir,
                        pTempDirEntry->OffsetToDirectory,
                        &pResourceSection.levels[1].pDir,
                        &pResourceSection.levels[1].pEntry);
                if (!ret)
                {
                    throw std::runtime_error(PE_PARSE_ERR "ResourceDirectory is null.");
                }

                pTempDirEntry = pResourceSection.levels[1].pEntry;
                for (auto i{ 0 };
                        i < (pResourceSection.levels[1].pDir->NumberOfIdEntries +
                            pResourceSection.levels[1].pDir->NumberOfNamedEntries);
                        i++, pTempDirEntry++)
                {
                    // Level 2
                    assert(pTempDirEntry->DataIsDirectory == 1); // level 2 points to DataDirectory
                    if (pTempDirEntry && pTempDirEntry->DataIsDirectory == 1)
                    {
                        ret = getResourceDirectoryAndEntry((BYTE*)pRootDir,
                                pTempDirEntry->OffsetToDirectory,
                                &pResourceSection.levels[2].pDir,
                                &pResourceSection.levels[2].pEntry);
                        if (!ret)
                        {
                            throw std::runtime_error(PE_PARSE_ERR "ResourceDirectory is null.");
                        }

                        pTempDirEntry = pResourceSection.levels[2].pEntry;
                        for (i = 0;
                                i < (pResourceSection.levels[2].pDir->NumberOfIdEntries +
                                    pResourceSection.levels[2].pDir->NumberOfNamedEntries);
                                i++, pTempDirEntry++)
                        {
                            // Level 3
                            assert(pTempDirEntry->DataIsDirectory == 0); // level 3 points to Data (leaf node)
                            pResourceSection.pData = (IMAGE_RESOURCE_DATA_ENTRY*)
                                ((BYTE*)pRootDir + pTempDirEntry->OffsetToData);

                            if (pResourceSection.pData)
                            {
                                // Size of data must be non-zero
                                assert(pResourceSection.pData->Size > 0);

                                auto dataOffset{ pResourceSection.pData->OffsetToData - pResourceSection.datadirRva };
                                pResourceSection.pDataBuffer = (BYTE*)pRootDir + dataOffset;
                                ret = true;
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
