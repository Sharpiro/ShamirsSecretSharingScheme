#include <slip39_wrapper.h>
#include <pbkdf2.h>
#include <wordlist.h>
#include <share.h>
#include <bit_container.h>
#include <get_insecure_randomness.h>

namespace Shamir {
	std::vector<std::vector<std::string>> fromEnthropy(const std::vector<uint8_t> & enthropy, uint16_t count, uint16_t threshold) {
		auto shares = distribute_secret_slip(enthropy, count, threshold);
		//auto shares = std::vector<bit_container>{ Shamir::bit_container(std::vector<uint8_t>{ 0, 89, 11, 250, 70, 145, 211, 143, 97, 174, 240, 49, 187, 167, 17, 233, 236, 44, 155, 0, 17, 18 }) };
		//auto shares = std::vector<bit_container>{ Shamir::bit_container(std::vector<uint8_t>{ 0, 89, 11, 250, 70, 145, 211, 143, 97, 174, 240, 49, 187, 167, 17, 233, 236, 44, 155, 4, 68, 128 }) };
		std::vector<std::vector<std::string>> output(shares.size());
		for (unsigned i = 0; i < shares.size(); ++i) {
			auto line = hexToPower2(shares.at(i), 10);
			auto entropySize = 16;
			auto linebits = (entropySize * 8 + 42);
			line.resize(linebits / 10 + (linebits % 10 ? 1 : 0));
			for (auto word : line) output.at(i).push_back(slip_words[word]);
		}
		return output;
	}

	std::vector<uint8_t> toEnthropy(const std::vector<std::vector<std::string>> & mnemonics) {
		std::vector<std::vector<uint8_t>> decoded_shares;
		for (unsigned i = 0; i < mnemonics.size(); ++i) {
			auto line = slip39ToNum(mnemonics.at(i));
			auto hex_line = power2ToHex(line, 10);

			/*	auto rebuiltIndexes = hexToPower2(hex_line, 10);
				auto linebits = (16 * 8 + 42);
				auto newSize = linebits / 10 + (linebits % 10 ? 1 : 0);
				rebuiltIndexes.resize(newSize);*/
			decoded_shares.push_back(hex_line);
		}
		return reconstruct_secret_slip(decoded_shares);
	}

	std::vector<uint8_t> toSeed(const std::vector<std::vector<std::string>> & mnemonics, const std::string & password) {
		return slip39_pbkdf2(toEnthropy(mnemonics), password);
	}
} // Shamir
