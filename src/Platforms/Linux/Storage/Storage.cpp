#include "Storage.h"

Storage::Storage() {

}

Storage::Storage(std::string) {

}

std::string Storage::read(std::filesystem::path file) {
    return "";
}

std::vector<uint8_t> Storage::readBinary(std::filesystem::path file) {
    std::vector<uint8_t> buffer;

    return buffer;
}

void Storage::write(std::filesystem::path file, std::string data) {
}

void Storage::write(std::filesystem::path file, std::vector<uint8_t> data) {
}

void Storage::remove(std::filesystem::path file) {
}

void Storage::rename(std::filesystem::path file, std::string name) {
}

bool Storage::exists(std::filesystem::path file) {
    return false;
}
#include <cstdlib>
#include <unistd.h>
#include "platform/paths/paths.h"

/*
 * Vault core hooks: $XDG_DATA_HOME/ClientWarden (default ~/.local/share/ClientWarden) for data,
 * next to the executable for resources.
*/
std::filesystem::path clientwarden::paths::dataDirectory() {
    const char* xdg = std::getenv("XDG_DATA_HOME");
    const char* home = std::getenv("HOME");
    std::filesystem::path base = xdg && *xdg ? std::filesystem::path(xdg)
        : std::filesystem::path(home ? home : ".") / ".local" / "share";
    return base / "ClientWarden";
}

std::filesystem::path clientwarden::paths::resourceDirectory() {
    char buffer[4096];
    ssize_t length = readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
    if (length <= 0) {
        return std::filesystem::current_path();
    }
    buffer[length] = '\0';
    return std::filesystem::path(buffer).parent_path();
}
