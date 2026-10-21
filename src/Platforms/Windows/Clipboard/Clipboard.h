#pragma once
#include <chrono>
#include <string>
#include <string_view>
#include <winrt/Windows.ApplicationModel.DataTransfer.h>
#include <winrt/Windows.Foundation.h>
#include <Windows.h>

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
