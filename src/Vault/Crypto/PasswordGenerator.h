#pragma once
#include <string>
#include <string_view>
#include <vector>

#include "Clientwarden.h"

namespace ClientWarden {
    /*
     * All output is drawn with unbiased rejection sampling from the
     * system CSPRNG.
    */
    class PasswordGenerator {
    public:
        struct Options {
            int length = 16;
            bool uppercase = true;
            bool numbers = true;
            bool symbols = false;
        };

        /*
         * Loads the passphrase word list (one word per line). An empty
         * list leaves Passphrase() unavailable.
        */
        explicit PasswordGenerator(std::string_view wordList = {});

        /*
         * Reads clientgen.txt from the app bundle.
        */
        static PasswordGenerator FromBundle();

        static SecretString Random(const Options& options);
        static SecretString Pin(int digits);
        SecretString Passphrase(int words, bool capitalize, char separator = '-') const;

    private:
        std::vector<std::string> words;
    };
}
