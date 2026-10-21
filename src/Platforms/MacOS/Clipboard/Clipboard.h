#pragma once
#include <chrono>
#include <string>
#include <string_view>

namespace ClientWarden {
    /*
     * Platform clipboard. Copy() clears the clipboard after clearAfter
     * unless something else has been copied in the meantime.
    */
    class Clipboard {
    public:
        void Copy(std::string_view text, std::chrono::seconds clearAfter);
        std::string Paste();
    };
}
