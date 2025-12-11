#include <map>
#include <fstream>
#include <iostream>
#include <filesystem>

#include <zstd.h>
#include <argparse.hpp>

#include "PackLib/config.h"

int main(int argc, char* argv[])
{
	std::setlocale(LC_ALL, "en_US.UTF-8");

	argparse::ArgumentParser program("PackMaker");

	program.add_argument("--input")
		.required()
		.help("Input folder to pack");

	program.add_argument("--output")
		.default_value("")
		.help("Output path to place newly created pack file");

	try {
		program.parse_args(argc, argv);
	}
	catch (const std::exception& ex) {
		std::cerr << ex.what() << std::endl;
		std::cerr << program;
		std::exit(EXIT_FAILURE);
	}

	std::filesystem::path input = program.get<std::string>("--input"), output = program.get<std::string>("--output");

	// we just normalize it here, because if it has a trailing slash, filename() will be empty
	// otherwise it returns the last part of the path
	if (input.filename().empty()) {
		input = input.parent_path();
	}

	output /= input.filename().replace_extension(".pck");

	std::ofstream ofs(output, std::ios::binary);
	if (!ofs.is_open()) {
		std::cerr << "Failed to open output file: " << output << std::endl;
		return EXIT_FAILURE;
	}

	std::map<std::filesystem::path, TPackFileEntry> entries;

	for (auto entry : std::filesystem::recursive_directory_iterator(input)) {
		if (!entry.is_regular_file())
			continue;

		std::filesystem::path relative_path = std::filesystem::relative(entry.path(), input);
		
		TPackFileEntry& file_entry = entries[relative_path];
		memset(&file_entry, 0, sizeof(file_entry));
		file_entry.file_size = entry.file_size();

		constexpr std::string_view ymir_work_prefix = "ymir work/";
		std::string rp_str = relative_path.generic_string();
		if (rp_str.compare(0, ymir_work_prefix.size(), ymir_work_prefix) == 0) {
			rp_str = (std::filesystem::path("d:/ymir work/") / rp_str.substr(ymir_work_prefix.size())).generic_string();
		}

		std::transform(rp_str.begin(), rp_str.end(), rp_str.begin(), [](unsigned char c) {
			return static_cast<char>(std::tolower(c));
		});

		rp_str.copy(file_entry.file_name, sizeof(file_entry.file_name) - 1);
	}

	TPackFileHeader header;
	memset(&header, 0, sizeof(header));
	header.entry_num = entries.size();
	header.data_begin = sizeof(TPackFileHeader) + sizeof(TPackFileEntry) * entries.size();

	CryptoPP::AutoSeededRandomPool rnd;
	rnd.GenerateBlock(header.iv, sizeof(header.iv));

	ofs.write((const char*) &header, sizeof(header));
	ofs.seekp(header.data_begin, std::ios::beg);

	CryptoPP::CTR_Mode<CryptoPP::Camellia>::Encryption encryption;
	encryption.SetKeyWithIV(PACK_KEY.data(), PACK_KEY.size(), header.iv, CryptoPP::Camellia::BLOCKSIZE);

	uint64_t offset = 0;
	for (auto& [path, entry] : entries) {
		std::ifstream ifs(input / path, std::ios::binary);
		if (!ifs.is_open()) {
			std::cerr << "Failed to open input file: " << (input / path) << std::endl;
			return EXIT_FAILURE;
		}

		static std::vector<char> buffer;
		buffer.resize(entry.file_size);

		if (!ifs.read(buffer.data(), entry.file_size)) {
			std::cerr << "Failed to read input file: " << (input / path) << std::endl;
			return EXIT_FAILURE;
		}

		size_t compress_bound = ZSTD_compressBound(entry.file_size);
		static std::vector<char> compressed_buffer;
		compressed_buffer.resize(compress_bound);

		entry.compressed_size = ZSTD_compress(compressed_buffer.data(), compress_bound, buffer.data(), entry.file_size, 17);
		if(ZSTD_isError(entry.compressed_size)) {
			std::cerr << "Failed to compress input file: " << (input / path) << " error: " << ZSTD_getErrorName(entry.compressed_size) << std::endl;
			return EXIT_FAILURE;
		}

		entry.offset = offset;

		entry.encryption = 0;
		if (path.has_extension() && path.extension() == ".py") {
			entry.encryption = 1;

			rnd.GenerateBlock(entry.iv, sizeof(entry.iv));
			encryption.Resynchronize(entry.iv, sizeof(entry.iv));
			encryption.ProcessData((uint8_t*)compressed_buffer.data(), (uint8_t*)compressed_buffer.data(), entry.compressed_size);
		}

		ofs.write(compressed_buffer.data(), entry.compressed_size);
		offset += entry.compressed_size;
	}

	ofs.seekp(sizeof(TPackFileHeader), std::ios::beg);
	encryption.Resynchronize(header.iv, sizeof(header.iv));
	
	for (auto& [path, entry] : entries) {
		TPackFileEntry tmp = entry;
		encryption.ProcessData((uint8_t*)&tmp, (uint8_t*)&tmp, sizeof(TPackFileEntry));
		ofs.write((const char*)&tmp, sizeof(TPackFileEntry));
	}

	return EXIT_SUCCESS;
}
