#pragma once
#include <string>
#include <mio/mmap.hpp>

#include "config.h"

class CBufferPool;

class CPack : public std::enable_shared_from_this<CPack>
{
public:
	CPack() = default;
	~CPack() = default;

	bool Open(const std::string& path, TPackFileMap& entries);
	bool GetFile(const TPackFileEntry& entry, TPackFile& result);
	bool GetFileWithPool(const TPackFileEntry& entry, TPackFile& result, CBufferPool* pPool);

private:
	TPackFileHeader m_header;
	mio::mmap_source m_file;

	CryptoPP::CTR_Mode<CryptoPP::Camellia>::Decryption m_decryption;
};