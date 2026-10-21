#pragma once
#import <Foundation/Foundation.h>
#import "clientwarden-Swift.h"
#include <vector>
#include "Model/ItemQuery.h"

/*
 * Shared by the items and navigation panels: turns query results into
 * the ItemElements the Swift lists display. Objective-C++ only, so it
 * stays out of the Swift bridging header.
 */
NSArray<ItemElement*>* MakeItemElements(const std::vector<ClientWarden::ItemSummary>& ciphers);
ItemType ItemTypeFor(ClientWarden::CipherType type);
ClientwardenImage* PlaceholderImageFor(ClientWarden::CipherType type);
