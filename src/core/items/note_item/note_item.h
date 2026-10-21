#pragma once
#include <string_view>

#include "items/generic_item/generic_item_type.h"

namespace clientwarden {
    /**
     * @brief A secure note (Bitwarden cipher type Note).
     */
    class NoteItem : public GenericItemType<NoteItem> {
    public:
        static constexpr CipherType c_type = CipherType::Note;

        using GenericItemType<NoteItem>::GenericItemType;
    };
}
