#ifndef RADIOTAP_HEADER
#define RADIOTAP_HEADER

#include "packet_header.hpp"

#define SIZE_RADIOTAP_HEADER_BITSTRING 56

struct radiotap_header {
	/* all bytes for radiotap_data 	*/
    uint8_t* radiotap_data;
};

class RadiotapHeader : public PacketHeader {
    public:
        /* Required Functions */
        void* get_raw();
        void set_raw(void *raw);
        void print_header(FILE *out);
        uint32_t get_header_len();
        void get_bitstring(std::vector<int8_t>  &to_fill, int8_t fill_with);
        void get_bitstring_header(std::vector<std::string> &to_fill);
    private:
      struct radiotap_header *raw = nullptr;
};

#endif
