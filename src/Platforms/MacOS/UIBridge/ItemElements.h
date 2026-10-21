#pragma once
#import <Foundation/Foundation.h>
#import "clientwarden-Swift.h"
#include <vector>
#include "items/cipher_query/cipher_query.h"

/*
 * Shared by the items and navigation panels: turns query results into
 * the ItemElements the Swift lists display. Objective-C++ only, so it
 * stays out of the Swift bridging header.
 */
NSArray<ItemElement*>* MakeItemElements(const std::vector<clientwarden::ItemSummary>& ciphers);
ItemType ItemTypeFor(clientwarden::CipherType type);
ClientwardenImage* PlaceholderImageFor(clientwarden::CipherType type);
