#pragma once
#include "generic_item.h"

namespace clientwarden {
    /**
     * @brief CRTP base giving typed items builder-style setters for the shared fields.
     *
     * The shared setters return Derived& so calls chain across shared and typed fields:
     *     item->setName("GitHub").setUsername("octocat").commit();
     *
     * @tparam Derived The concrete item class (e.g. LoginItem)
     */
    template <typename Derived> class GenericItemType : public GenericItem {
    public:
        using GenericItem::GenericItem;

        /**
         * @brief Sets the name.
         *
         * @param name The new name
         * @return This item, for chaining
         */
        Derived& setName(std::string_view name) {
            GenericItem::setName(name);
            return static_cast<Derived&>(*this);
        }

        /**
         * @brief Sets the notes.
         *
         * @param notes The new notes
         * @return This item, for chaining
         */
        Derived& setNotes(std::string_view notes) {
            GenericItem::setNotes(notes);
            return static_cast<Derived&>(*this);
        }

        /**
         * @brief Files the item under a folder.
         *
         * @param folder_id The folder id
         * @return This item, for chaining
         */
        Derived& setFolder(std::string_view folder_id) {
            GenericItem::setFolder(folder_id);
            return static_cast<Derived&>(*this);
        }

        /**
         * @brief Removes the item from its folder.
         *
         * @return This item, for chaining
         */
        Derived& removeFolder() {
            GenericItem::removeFolder();
            return static_cast<Derived&>(*this);
        }

        /**
         * @brief Appends a custom field.
         *
         * @param type The field kind
         * @param name The field name
         * @param value The value
         * @return This item, for chaining
         */
        Derived& addField(CustomFieldType type, std::string_view name, std::string_view value) {
            GenericItem::addField(type, name, value);
            return static_cast<Derived&>(*this);
        }

        /**
         * @brief Removes a custom field.
         *
         * @param name The field name
         * @return This item, for chaining
         */
        Derived& removeField(std::string_view name) {
            GenericItem::removeField(name);
            return static_cast<Derived&>(*this);
        }

        /**
         * @brief Removes all custom fields.
         *
         * @return This item, for chaining
         */
        Derived& clearFields() {
            GenericItem::clearFields();
            return static_cast<Derived&>(*this);
        }

        /**
         * @brief Marks or unmarks as favourite.
         *
         * @param favorite True to favourite
         * @return This item, for chaining
         */
        Derived& setFavorite(bool favorite) {
            GenericItem::setFavorite(favorite);
            return static_cast<Derived&>(*this);
        }

        /**
         * @brief Turns master password re-prompt on or off.
         *
         * @param reprompt True to require re-prompt
         * @return This item, for chaining
         */
        Derived& setReprompt(bool reprompt) {
            GenericItem::setReprompt(reprompt);
            return static_cast<Derived&>(*this);
        }
    };
}
