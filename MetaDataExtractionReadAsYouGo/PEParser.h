#pragma once
#include <Windows.h>
#include <string>
#include <iostream>
#include <vector>
#include <tuple>
#include <functional>
#include "File.h"


<-- Use enum classes
//namespace uc
//{
    enum PEfileType
    {
        PE_TYPE_NONE  = 0x0,
        PE_TYPE_32BIT = 0x1,
        PE_TYPE_64BIT = 0x2
    };

    typedef struct
    {
		std::unique_ptr<IMAGE_RESOURCE_DIRECTORY[]> spDir;
		std::shared_ptr<IMAGE_RESOURCE_DIRECTORY_ENTRY> spEntry;
    }resource_tree_level_t;

	typedef struct
	{
		ULONG datadirRva;
		ULONG offset;
		resource_tree_level_t levels[3];
		std::unique_ptr<BYTE[]> spDataBuffer;
		DWORD dataBufferSize;
	} resource_section_info_t;


using version_value_t = std::pair<std::wstring, std::wstring>;
using version_values_t = std::vector<version_value_t>;

<-- Use inline functions wherever possible

#define ALIGN_32BIT_BOUNDRY(i)		(i) = ((i) + 0x3) & (~0x3)
#define VERINFO_PARSE_ERR           "VersionInfo parse error: "
#define PE_PARSE_ERR				"Not a valid PE: "

#define VS_VERSION_STRING			(L"VS_VERSION_INFO")
#define VS_VERSION_STRING_LEN		(sizeof (VS_VERSION_STRING))/sizeof(wchar_t)

#define FILE_INFO_STRING            (L"StringFileInfo")
#define FILE_INFO_STRING_LEN		sizeof (FILE_INFO_STRING)/sizeof(wchar_t)

#define VAR_FILE_INFO_STRING        (L"VarFileInfo")
#define VAR_FILE_INFO_STRING_LEN    sizeof (VAR_FILE_INFO_STRING)/sizeof(wchar_t)

#define ENG_LANG_CODE_STRING        (L"09")

#define SEEK_AND_READ(offset,buf,type,num,success)\
do{\
    m_pSeek(offset);\
    buf = std::make_unique<type[]>(num);\
    success = m_pRead((BYTE*)buf.get(), sizeof(type)*num);\
}while(0)

#define SEEK_AND_READ_SHARED(offset,buf,type,num,success)\
do{\
    m_pSeek(offset);\
    buf = std::make_shared<type>();\
    success = m_pRead((BYTE*)buf.get(), sizeof(type));\
}while(0)

#pragma pack(1)
	typedef struct version_info_st {
		UINT16 length;
		UINT16 val_length;
		UINT16 type;
		wchar_t key[VS_VERSION_STRING_LEN];
		BYTE* opaque;
	} version_info_t;
#pragma pack()

#pragma pack(1)
	typedef struct string_file_info_st {
		UINT16 length;
		UINT16 val_length;
		UINT16 type;
		wchar_t key[FILE_INFO_STRING_LEN];
		char* opaque;
	} string_file_info_t;
#pragma pack()

#pragma pack(1)
	typedef struct string_tbl_st {
		UINT16 length;
		UINT16 val_length;
		UINT16 type;
		wchar_t key[8];
		char* opaque;
	} string_tbl_t;
#pragma pack()

#pragma pack(1)
	typedef struct string_st {
		UINT16 length;
		UINT16 val_length;
		UINT16 type;
		wchar_t opaque[1];
	} string_t;
#pragma pack()

    class PEParser
    {
        public:
			using pSeek_t = std::function<bool(long)>;
			using pRead_t = std::function<bool(void*, const DWORD)>;

			PEParser();

           	bool parse(
				const std::string& fileName,
				pSeek_t pSeek,
				pRead_t pRead);

			bool parseResourceDir(
				const LPWSTR resourceId,
				resource_section_info_t& pResourceSection);

            bool parseVersionInfo(
				const resource_section_info_t& pResourceSection,
				version_values_t& vi);

			const uint32_t getSubsystem() const;

        private:
            static constexpr DWORD BUF_SIZE = (8 * 1024); // 8k
			static constexpr uint32_t MAX_NUM_SECTIONS = 100;
			static constexpr uint32_t MAX_NUM_DATA_DIRECTORIES = 20;
			static constexpr uint32_t MAX_NUM_SUBSYSTEMS = 20;



            std::string m_fileName;
            PEfileType m_flags;
            uint32_t m_numSections;
			uint32_t m_numDataDirectories;
			uint32_t m_subSystem;
			uint32_t m_bufSize;
			pSeek_t  m_pSeek;
			pRead_t  m_pRead;

			std::unique_ptr<IMAGE_DOS_HEADER[]> m_spDosHdr; /* Dos header */
			std::unique_ptr<IMAGE_NT_HEADERS[]> m_spPeHdr;  /* PE header */
			IMAGE_NT_HEADERS32* m_pNtHdr32;				/* Nt header 32-bit */
            IMAGE_NT_HEADERS64* m_pNtHdr64;				/* Nt header 64-bit */
            IMAGE_FILE_HEADER* m_pFileHdr;				/* File header */
            IMAGE_OPTIONAL_HEADER32* m_pOptionalHdr32;	/* Optional header 32 bit*/
            IMAGE_OPTIONAL_HEADER64* m_pOptionalHdr64;	/* Optional header 64 bit */
			std::unique_ptr<IMAGE_SECTION_HEADER[]> m_spSectionTable; /* Section table */
            
        private:
			template <typename T_IMAGE_NT_HEADER, typename T_IMAGE_OPTIONAL_HEADER>
			bool parsePeFileType(
				const PEfileType PEfileTypeFlags,
				T_IMAGE_NT_HEADER& pNtHdr,
				T_IMAGE_OPTIONAL_HEADER& pOptionalHdr);

			bool getResourceSection(
				resource_section_info_t& pResourceSection);
    };
//}

