#include "Clipboard.h"

namespace ClientWarden {
    void Clipboard::Copy(std::string_view, std::chrono::seconds) {
    }

    std::string Clipboard::Paste() {
        return {};
    }
}
