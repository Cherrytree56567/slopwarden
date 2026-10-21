#include "platform/paths/paths.h"

/*
 * Tests never touch the real filesystem through these; they inject in-memory stores.
*/
namespace clientwarden::paths {
    std::filesystem::path dataDirectory() {
        return std::filesystem::temp_directory_path() / "clientwarden-tests";
    }

    std::filesystem::path resourceDirectory() {
        return std::filesystem::temp_directory_path() / "clientwarden-tests-resources";
    }
}
