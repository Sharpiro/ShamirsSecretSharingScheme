#ifndef SHARE_H
#define SHARE_H 1

#include <bit_container.h>

#include <vector>
#include <cstdint>

namespace Shamir {
	std::vector<uint8_t> reconstruct_secret_slip(const std::vector<std::vector<uint8_t>> & raw_shares);
	std::vector<bit_container> distribute_secret_slip(const std::vector<uint8_t> & secret, uint16_t count, uint16_t threshold);

} // Shamir

Shamir::bit_container & append_checksum(Shamir::bit_container & share);
Shamir::bit_container mkshare(uint16_t index, uint16_t threshold, const std::vector<uint8_t> & dat);
#endif
