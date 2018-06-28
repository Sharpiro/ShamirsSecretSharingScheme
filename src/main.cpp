#pragma comment(lib, "Ws2_32.lib")

#include <slip39_wrapper.h>


#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <sstream>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>

namespace {
	void print_help(std::ostream & ost, const char n[]) {
		ost << n << " command  [ params ]\n";
		ost << "\tcommands:\n\t\tdisthex <count> <threshold>\t\tReads hex-encoded enthropy\n\t\t";
		ost << "distraw <count> <threshold>\t\tReads ASCII text.\n\t\t";
		ost << "mergehex\t\t\t\tReads shares from stdin, one share per line. Correct number of shares must be supplied.\n\t\t";
		ost << "mergeseed <passphrase>\t\t\tSame as mergehex, but applies PBKDF2-SHA256 on the output (see SLIP39).\n\t\t";
		ost << "mergeascii\t\t\t\tSame as mergehex, but prints result as ascii string. This makes sen\n\t\t\t\t\t\t\t";
		ost << "only to shares constructed from ascii text. The result may be cropped by null-char.\n\t\t";
		ost << "help\t\t\t\t\tPrints this help and exits." << std::endl;
	}

	void print_help_quit(std::ostream & ost, const char n[]) {
		print_help(ost, n);
		exit(1);
	}

	std::vector<uint8_t> readhex(std::istream & ist) {
		std::vector<uint8_t> output;
		std::string s;
		std::getline(ist, s);
		std::stringstream ss;
		ss << s;
		ss >> s; /// read whole line but take only first string
		for (unsigned i = 0; i < s.size() / 2; ++i) {
			unsigned tmp;
			if (sscanf(s.c_str() + 2 * i, "%02x", &tmp) == 1)
				output.push_back((uint8_t)tmp);
		}
		return output;
	}

	std::vector<std::string> readmnemonics(std::istream & ist) {
		std::vector<std::string> output;
		std::string s;
		std::getline(ist, s);
		std::stringstream ss;
		ss << s;
		while (ss) {
			ss >> s;
			if (ss) output.push_back(s);
		}
		return output;
	}

	void disthex(const char *c, const char *t) {
		std::cout << "Distributes hex encoded enthropy into " << c << " shares with reconstruction threshold " << t << ":\n";
		long count, threshold;
		char * cc;
		count = strtol(c, &cc, 10);
		if (errno == ERANGE) print_help_quit(std::cerr, "program");
		threshold = strtol(t, &cc, 10);
		if (errno == ERANGE) print_help_quit(std::cerr, "program");
		auto raw_enthropy = readhex(std::cin);
		auto output = Shamir::fromEnthropy(raw_enthropy, count, threshold);
		for (auto &&it : output) {
			for (auto &ii : it) std::cout << ii << ' ';
			std::cout << std::endl;
		}

	}

	void distraw(const char *c, const char *t) {
		std::cout << "distributes arbibrary ascii text into " << c << " shares with reconstruction threshold " << t << ":\n";
		long count, threshold;
		char * cc;
		count = strtol(c, &cc, 10);
		if (errno == ERANGE) print_help_quit(std::cerr, "program");
		threshold = strtol(t, &cc, 10);
		if (errno == ERANGE) print_help_quit(std::cerr, "program");
		std::string msg;
		std::getline(std::cin, msg);
		std::vector<uint8_t> v_msg(msg.begin(), msg.end());
		for (unsigned i = (4 - (v_msg.size() % 4)) % 4; i > 0; --i) v_msg.push_back(0);
		std::cout << v_msg.size() << '\n' << ((char *)v_msg.data()) << std::endl;
		auto output = Shamir::fromEnthropy(v_msg, count, threshold);
		for (auto &&it : output) {
			for (auto &ii : it) std::cout << ii << ' ';
			std::cout << std::endl;
		}
	}

	void mergeseed(const char *p) {
		std::cout << "Merges into seed with passphrase: '" << p << "':\n";
		std::vector<std::vector<std::string>> shares;
		while (std::cin) {
			shares.push_back(readmnemonics(std::cin));
			if (shares.back().empty()) shares.pop_back();
		}
		auto out = Shamir::toSeed(shares, p);
		for (auto it : out) std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)it;
		std::cout << std::endl;
	}

	void mergehex() {
		std::cout << "Merges shares into hex encoded enthropy:\n";
		std::vector<std::vector<std::string>> shares;
		while (std::cin) {
			shares.push_back(readmnemonics(std::cin));
			if (shares.back().empty()) shares.pop_back();
		}
		auto out = Shamir::toEnthropy(shares);
		for (auto it : out) std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)it;
		std::cout << std::endl;
	}

	/// reconstructs raw share and prints as a c-string
	void mergeascii() {
		std::cout << "Merges shares and prints the result as ASCII characters\n";
		std::vector<std::vector<std::string>> shares;
		while (std::cin) {
			shares.push_back(readmnemonics(std::cin));
			if (shares.back().empty()) shares.pop_back();
		}
		auto out = Shamir::toEnthropy(shares);
		std::cout << ((const char *)out.data()) << std::endl;
	}

	void cli_args(int argc, char * argv[]) {
		if (std::strncmp(argv[1], "disthex", 8) == 0) {
			if (argc != 4) print_help_quit(std::cerr, argv[0]);
			disthex(argv[2], argv[3]);
			return;
		}
		else if (std::strncmp(argv[1], "distraw", 8) == 0) {
			if (argc != 4) print_help_quit(std::cerr, argv[0]);
			distraw(argv[2], argv[3]);
			return;
		}
		else if (std::strncmp(argv[1], "mergeseed", 10) == 0) {
			if (argc != 3) print_help_quit(std::cerr, argv[0]);
			mergeseed(argv[2]);
			return;
		}
		else if (std::strncmp(argv[1], "mergehex", 9) == 0) {
			mergehex();
			return;
		}
		else if (std::strncmp(argv[1], "mergeascii", 11) == 0) {
			mergeascii();
			return;
		}
		else if (std::strncmp(argv[1], "help", 5) == 0) {
			print_help(std::cout, argv[0]);
			exit(0);
		}
		else {
			print_help_quit(std::cerr, argv[0]);
		}
	}
}

//int main(int argc, char * argv[]) {
//	if (argc == 1) {
//		print_help(std::cerr, argv[0]);
//		return 1;
//	}
//	try {
//		cli_args(argc, argv);
//	} catch (const char *s) {
//		std::cerr << s << std::endl;
//		exit(1);
//	}
//	return 0;
//}

std::vector<int> resizeWordIndex(std::vector<int> &data, int entropySize) {
	auto linebits = (entropySize * 8 + 42);
	data.resize(linebits / 10 + (linebits % 10 ? 1 : 0));
	return data;
}

#include <wordlist.h>
#include <share.h>
#include <bit_container.h>
#include <share.h>
#include <portable_endian.h>

int main()
{
	try
	{
		//auto data = 16;
		//auto hToBE = htobe16(data);
		//auto hToLE = htole16(data);
		//auto entropy = std::vector<uint8_t>{ 170, 187, 204, 221 };
		//auto shareIndexes = std::vector<int>{ 130, 512, 612, 227, 732, 733, 437, 512 };
		//auto hexVector = Shamir::power2ToHex(shareIndexes, 10);
		//auto rebuiltIndex = Shamir::hexToPower2(hexVector, 10);
		//auto rebuiltShareIndexes = resizeWordIndex(rebuiltIndex, entropy.size());

		//auto res = Shamir::reconstruct_secret_slip(std::vector<std::vector<uint8_t>>{hexVector});
		//auto res2 = Shamir::fromEnthropy(entropy, 3, 2); // need randomizer

		//auto mnemonic = std::vector<std::string>{ "acid", "reward", "furnace", "beauty", "warfare", "rich", "town", "awkward" };
		/*auto mnemonic = std::vector<std::string>{ "acid", "glance" ,"scatter" ,"multiply" ,"muscle" ,"evolve" ,"vote" ,"hedgehog" ,"vanish" ,"shoe" ,"road" ,"sense" ,"ugly" ,"raise" ,"sister" ,"scout" ,"educate" };
		auto mnemonics = std::vector<std::vector<std::string>>{ mnemonic };
		auto num_share = Shamir::toEnthropy(mnemonics);*/
		auto temp = Shamir::fromEnthropy(std::vector<uint8_t>{0x09, 0x08, 0x07, 0x06}, 3, 2);

		//push_n test
		/*auto data = Shamir::bit_container(std::vector<uint8_t>{ 0, 89, 11, 250, 70, 145, 211, 143, 97, 174, 240, 49, 187, 167, 17, 233, 236, 44, 155, 0, 17, 18 });
		auto tmp_cont = mkshare(1, 2, data);*/
		//append_checksum(data);
		//data.push_n(std::vector<uint8_t>{17, 18, 214, 226}, 16);
	}
	catch (const char *s)
	{
		std::cerr << s << std::endl;
		exit(1);
	}
	return 0;
}
