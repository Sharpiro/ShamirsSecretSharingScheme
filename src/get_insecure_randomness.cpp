#include <get_insecure_randomness.h>
#include <random>

void pseudo_random_fill(std::vector<uint8_t> & chunk) {
	std::random_device rd;
	std::uniform_int_distribution<int> dist(0, 255);
	for (auto && i : chunk)
	{
		i = (dist(rd) & 0xFF);
	}
}

//void pseudo_random_fill(std::vector<uint8_t> & chunk) {
//	auto counter = 0;
//	for (auto && i : chunk)
//	{
//		i = ++counter;
//	}
//}