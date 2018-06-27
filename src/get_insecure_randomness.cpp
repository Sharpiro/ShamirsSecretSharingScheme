#include <get_insecure_randomness.h>
#include <random>

void pseudo_random_fill(std::vector<uint8_t> & chunk) {
	std::random_device rd;
	std::uniform_int_distribution<int> dist(0, 255);
	std::vector<char> data(1000);
	for (auto && i : chunk)
	{
		i = (dist(rd) & 0xFF);
	}
}
