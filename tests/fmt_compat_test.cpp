#define _SECURE_SCL 1
#define FMT_HEADER_ONLY
#include "spdlog/fmt/bundled/format.h"
#include <cassert>
#include <iterator>
int main()
{
    std::string output;
    fmt::format_to(std::back_inserter(output), "{} {:.2f} 0x{:X}", "audio", 0.65, 255);
    assert(output == "audio 0.65 0xFF");
    fmt::memory_buffer buf;
    fmt::format_to(buf, "{}", std::string(4096, 'x'));
    assert(buf.size() == 4096);
}
