#include "Clipboard.h"

#include <thread>

namespace ClientWarden {
    void Clipboard::Copy(std::string_view str, std::chrono::seconds clearAfter) {
        winrt::Windows::ApplicationModel::DataTransfer::DataPackage dataPackage;

        winrt::hstring hstr = winrt::to_hstring(str);

        dataPackage.SetText(hstr);

        winrt::Windows::ApplicationModel::DataTransfer::ClipboardContentOptions options;
        options.IsRoamable(false);
        options.IsAllowedInHistory(false);

        winrt::Windows::ApplicationModel::DataTransfer::Clipboard::SetContentWithOptions(dataPackage, options);

        DWORD targetedSequenceNumber = ::GetClipboardSequenceNumber();

        std::thread([clearAfter, targetedSequenceNumber]() {
            std::this_thread::sleep_for(clearAfter);
            if (GetClipboardSequenceNumber() == targetedSequenceNumber) {
                winrt::Windows::ApplicationModel::DataTransfer::DataPackage emptyPackage;
                emptyPackage.SetText(L"");
                    
                winrt::Windows::ApplicationModel::DataTransfer::ClipboardContentOptions emptyOptions;
                emptyOptions.IsRoamable(false);
                emptyOptions.IsAllowedInHistory(false);
                    
                winrt::Windows::ApplicationModel::DataTransfer::Clipboard::SetContentWithOptions(emptyPackage, emptyOptions);
            }
        }).detach();

        if (!hstr.empty()) {
            SecureZeroMemory(const_cast<wchar_t*>(hstr.data()), hstr.size() * sizeof(wchar_t));
        }
    }

    std::string Clipboard::Paste() {
        std::string str;
        winrt::Windows::ApplicationModel::DataTransfer::DataPackageView content = winrt::Windows::ApplicationModel::DataTransfer::Clipboard::GetContent();

        if (content.Contains(winrt::Windows::ApplicationModel::DataTransfer::StandardDataFormats::Text())) {
            winrt::hstring hstr = content.GetTextAsync().get();
            str = winrt::to_string(hstr);
            if (!hstr.empty()) {
                SecureZeroMemory(const_cast<wchar_t*>(hstr.data()), hstr.size() * sizeof(wchar_t));
            }
        }
        return str;
    }
}