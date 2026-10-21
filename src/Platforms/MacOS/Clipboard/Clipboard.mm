#include "Clipboard.h"
#import <Cocoa/Cocoa.h>
#include <thread>

namespace ClientWarden {
    void Clipboard::Copy(std::string_view text, std::chrono::seconds clearAfter) {
        NSPasteboard* pasteboard = [NSPasteboard generalPasteboard];
        [pasteboard clearContents];

        NSString* nsStr = [[NSString alloc] initWithBytes:text.data() length:text.size() encoding:NSUTF8StringEncoding];

        /*
         * ConcealedType asks clipboard managers not to record the value.
        */
        NSArray* types = @[NSPasteboardTypeString, @"org.nspasteboard.ConcealedType"];
        [pasteboard declareTypes:types owner:nil];
        [pasteboard setString:nsStr forType:NSPasteboardTypeString];
        [pasteboard setString:@"" forType:@"org.nspasteboard.ConcealedType"];

        NSInteger targetedChangeCount = [pasteboard changeCount];

        std::thread([clearAfter, targetedChangeCount]() {
            std::this_thread::sleep_for(clearAfter);
            NSPasteboard* pb = [NSPasteboard generalPasteboard];
            if ([pb changeCount] == targetedChangeCount) {
                [pb clearContents];
            }
        }).detach();
    }

    std::string Clipboard::Paste() {
        NSString* nsStr = [[NSPasteboard generalPasteboard] stringForType:NSPasteboardTypeString];
        return nsStr != nil ? std::string([nsStr UTF8String]) : std::string();
    }
}
