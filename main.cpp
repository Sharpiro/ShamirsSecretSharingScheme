#include <shamirmulti.h>
#include <multiblock.h>
#include <wordlist.h>


#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <set>
#include <regex>

using namespace std;

namespace {
	std::string program_name;

	int readint(const std::string s) {
		const char * oor = "Number out of range";
		if (s.size() > 3) throw oor;
		int out = (int) std::strtol(s.c_str(), NULL, 10);
		if (out == 0) throw "Invalid number";
		if (out > 32) throw oor;
		return out;
	}

	std::string help(const std::string & topic = std::string("")) { // help_section for the future
		return std::string("Usage: " + program_name + " [-d|-m] -t <1-32> -n <1-32>\n\td...distribute\n\tm...merge\n\tt...threshold\n\tn...count\n\tt<=n\n");
	}
}

void process_clarg(bool & merg, int & count, int & threshold, int argc, const char * argv[]) {
	if (argc == 1) {
		std::cerr << help();
		exit(1);
	}
	count = 0;
	threshold = 0;
	merg = false;

	std::regex help_arg(R"(.*(?:\s|^)(-h|--help)(?:\s+(\w+)\b)?.*)");
	std::regex merg_arg(R"(.*(?:\s|^)(?:-m\s*|--merge)\b.*)");
	std::regex dist_arg(R"(.*(?:\s|^)(-d|--distribute)\b.*)");
	std::regex threshold_arg(R"(.*(?:\s|^)(-t|--threshold)\s*(\d{1,2})\b.*)");
	std::regex count_arg(R"(.*(?:\s|^)(-n|--count)\s*(\d{1,2})\b.*)");
	std::smatch clarg_match;
	std::string commandline;
	for (int i = 1; i < argc; ++i) {
		commandline.append(argv[i]);
		commandline.push_back(' ');
	}
	commandline.pop_back();
	if (std::regex_match(commandline, clarg_match, help_arg)) {
		std::cout << help(clarg_match[clarg_match.size()-1]);
		exit(0);
	}
	if (std::regex_match(commandline, clarg_match, merg_arg)) {
		merg = true;
	}
	if (std::regex_match(commandline, clarg_match, dist_arg)) {
		//std::cout << clarg_match[0] << " distribujiiiiii" << std::endl;
		if (merg) {
			std::cerr << "Cannot merge and distribute at the same time" << std::endl;
			exit(1);
		}
	}
	if (std::regex_match(commandline, clarg_match, threshold_arg)) {
		threshold = readint(clarg_match[clarg_match.size()-1]);
	}
	if (std::regex_match(commandline, clarg_match, count_arg)) {
		count = readint(clarg_match[clarg_match.size()-1]);
		if (threshold > count) {
			std::cerr << "Number of shares must be greater or equal to threshold" << std::endl;
			exit(1);
		}
	}
	if (!merg && (threshold * count == 0) ) throw "Inconsistent command line arguments";
}
void distribute(int threshold, int count) {
	std::cout << "Enter BIP39 mnemonic seed:\n";
	char word[512];
	/// read BIP39 seed
	std::cin.getline(word, 512);
	if (std::cin.fail()) throw "Problem with reading BIP mnemonic";
	std::stringstream ss;
	ss << word;
	std::string tmpw;
	std::vector<std::string> mnemonic;
	while ( true ) {
		ss >> tmpw;
		if ( ss.fail() ) break;
		mnemonic.push_back(tmpw);
	}
	try {
		auto seed = Shamir::power2ToHex(Shamir::bip39ToNum(mnemonic), 11);
		Shamir::check_bip39_checksum(seed);
		auto raw_shares = Shamir::distribute(seed, threshold, count);
		int total_share_bits = seed.size()*8 + 42;
		for (auto sh: raw_shares) {
			auto slip_words_num = Shamir::hexToPower2(sh,10);
			if (slip_words_num.size()*10 - total_share_bits >= 10) slip_words_num.pop_back(); /// drop the last word if it does not encode any information
			for (auto it: slip_words_num) {
				std::cout << slip_words[it] << " ";
			}
			std::cout << std::endl;
		}

	} catch (const char *s) {
		std::cerr << s << std::endl;
		exit(1);
	}

}

void process_share(std::vector<uint8_t> & hex_share, unsigned & index, unsigned & threshold) {
	if (threshold > 0) std::cout << index << " out of " << threshold<< " shares entered. Enter another share:" << std::endl;
	else std::cout << index << " out of ??" << " shares entered. Enter another share:" << std::endl;
	char word[512];

	
	std::cin.getline(word, 512);
	if (std::cin.fail()) throw "Problem with reading BIP mnemonic";
	std::stringstream ss;
	ss << word;
	if (std::strlen(word) == 0) {
		index = 0;
		threshold = 0;
		return;
	}
	std::string tmpw;
	std::vector<std::string> mnemonic;
	while ( true ) {
		ss >> tmpw;
		if ( ss.fail() ) break;
		mnemonic.push_back(tmpw);
	}
	try {
		auto num_share = Shamir::slip39ToNum(mnemonic);
		hex_share = Shamir::power2ToHex(num_share, 10);
		int secret_length = ((num_share.size() * 10 - 42)/32)*4;
		int share_bytes = (secret_length*8 + 42)/8;
		share_bytes += (share_bytes % 8) ? 1 : 0;
		hex_share.resize(share_bytes); /// stripp zero byte introduced by successive zero-padding during 10-bit array conversion to 8-bit array

		share preview(hex_share);
		index = preview.index;
		threshold = preview.threshold;

	} catch (const char * s) {
		std::cerr << s << std::endl;
		threshold = 0;
		index = 0;
	}
}

void merge() {
	std::vector<uint8_t> raw_share;
	std::vector<std::vector<uint8_t>> all_shares;
	unsigned count(1), index(0), threshold(0), fresh_threshold(0);
	std::set<unsigned> indices;
	while (threshold == 0)
		process_share(raw_share, index, threshold);
	all_shares.reserve(threshold);
	all_shares.push_back(raw_share);

	indices.insert(index);
	while (count < threshold) {
		index = count;
		fresh_threshold = threshold;
		raw_share.clear();
		process_share(raw_share, index, fresh_threshold);
		if (fresh_threshold == 0) continue; /// reading went wrong, give it another try
		if (fresh_threshold != threshold) throw "Inconsistent shares. Thresholds differ.";
		if (indices.find(index) != indices.cend()) {
			std::cout << "Share with current index already given. Give another one." << std::endl;
			continue;
		}
		indices.insert(index);
		all_shares.push_back(raw_share);
		++count;
	}
	try {
		auto secret = Shamir::reconstruct(all_shares);
		int total_mnemonic_bits = secret.size()/4*33;
		auto secret_bip39 = Shamir::hexToPower2(Shamir::append_bip39_checksum(secret), 11);
		if (secret_bip39.size() * 11 - total_mnemonic_bits >= 11) secret_bip39.pop_back(); /// drop the last word if it does not encode any information
		std::cout << "Reconstructed BIP39 seed:";
		for (auto it: secret_bip39) {
			auto word = bip_words[it];
			std::cout << std::setw(word.size() + 1) << word;
		}
		std::cout << std::endl;
	} catch (const char * s) {
		std::cerr << s << std::endl;
	}
}

// int main(int argc, const char* argv[]) {
// 	bool bip2slip(true);
// 	int threshold, count;
// 	try {
// 		process_clarg(bip2slip, count, threshold, argc, argv);
// 	} catch (const char *s) {
// 		std::cerr << "Error: " << s << std::endl;
// 		exit(0);
// 	}
// 	if (bip2slip)
// 		distribute((unsigned) threshold, (unsigned) count);
// 	else 
// 		merge();
// 	return 0;
// }

// int main(int argc, const char* argv[]) {
// 	program_name = argv[0];
// 	bool merg;
// 	int threshold, count;
// 	try {
// 		process_clarg(merg, count, threshold, argc, argv);
// 	} catch (const char *s) {
// 		std::cerr << "Error: " << s << std::endl;
// 		exit(0);
// 	}
// 	if (merg)
// 		merge();
// 	else 
// 		distribute((unsigned) threshold, (unsigned) count);
// 	return 0;
// }

template <class T, class T2>
void printBuffer(const std::vector<T>& buffer, const char* message){
		std::cout << message << std::endl;
		for (auto i: buffer)
  			std::cout << (T2)i << ' ';
		std::cout << std::endl;
}

int main(int argc, const char* argv[]) {
		auto mnemonic = std::vector<std::string>{"catch", "lemon", "often", "despair", "resist", "response", "hour", "lemon"};
		auto num_share = Shamir::slip39ToNum(mnemonic);
		printBuffer<int, int>(num_share, "mnemonic");
		// auto num_share = std::vector<int>{130, 512, 612, 227, 732, 733, 437, 512};
		auto hex_share = Shamir::power2ToHex(num_share, 10);
		printBuffer<uint8_t, int>(hex_share, "hex share");

		int secret_length = ((num_share.size() * 10 - 42)/32)*4;
		int share_bytes = (secret_length*8 + 42)/8;
		share_bytes += (share_bytes % 8) ? 1 : 0;
		hex_share.resize(share_bytes); /// stripp zero byte introduced by successive zero-padding during 10-bit array conversion to 8-bit array
		share preview(hex_share);
		printBuffer<uint8_t, int>(preview.data, "preview");

		auto index = preview.index;
		std::cout << index << std::endl;
		auto threshold = preview.threshold;
		std::cout << threshold << std::endl;
}
