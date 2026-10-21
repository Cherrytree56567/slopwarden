#include <jni.h>
#include <string>
#include <vector>
#include "Vault.h"

namespace {
    jobject getLucideIcon(JNIEnv* env, const char* iconName) {
        jclass lucideClass = env->FindClass("com/composables/icons/lucide/Lucide");
        if (lucideClass == nullptr) {
            env->ExceptionClear();
            return nullptr;
        }

        jfieldID field = env->GetStaticFieldID(lucideClass, iconName, "Landroidx/compose/ui/graphics/vector/ImageVector;");
        jobject icon = field != nullptr ? env->GetStaticObjectField(lucideClass, field) : nullptr;
        if (field == nullptr) {
            env->ExceptionClear();
        }

        env->DeleteLocalRef(lucideClass);
        return icon;
    }

    jobject makeUuid(JNIEnv* env, const std::string& uuid) {
        jclass uuidClass = env->FindClass("java/util/UUID");
        jmethodID fromString = env->GetStaticMethodID(uuidClass, "fromString", "(Ljava/lang/String;)Ljava/util/UUID;");

        jstring uuidString = env->NewStringUTF(uuid.c_str());
        jobject result = env->CallStaticObjectMethod(uuidClass, fromString, uuidString);

        env->DeleteLocalRef(uuidString);
        env->DeleteLocalRef(uuidClass);
        return result;
    }

    jobject getItemType(JNIEnv* env, const char* typeName) {
        jclass itemTypeClass = env->FindClass("com/ct5/clientwarden/ItemType");
        if (itemTypeClass == nullptr) {
            env->ExceptionClear();
            return nullptr;
        }

        jfieldID field = env->GetStaticFieldID(itemTypeClass, typeName, "Lcom/ct5/clientwarden/ItemType;");
        jobject type = field != nullptr ? env->GetStaticObjectField(itemTypeClass, field) : nullptr;
        if (field == nullptr) {
            env->ExceptionClear();
        }

        env->DeleteLocalRef(itemTypeClass);
        return type;
    }

    jobject makeItemList(JNIEnv* env, const std::vector<jobject>& items) {
        jclass arrayListClass = env->FindClass("java/util/ArrayList");
        jmethodID constructor = env->GetMethodID(arrayListClass, "<init>", "()V");
        jmethodID addMethod = env->GetMethodID(arrayListClass, "add", "(Ljava/lang/Object;)Z");

        jobject list = env->NewObject(arrayListClass, constructor);
        for (jobject item : items) {
            env->CallBooleanMethod(list, addMethod, item);
            env->DeleteLocalRef(item);
        }

        env->DeleteLocalRef(arrayListClass);
        return list;
    }

    /*
     * Kotlin's ItemType only knows the original five types; newer ones are
     * shown as logins until the UI grows them.
    */
    std::pair<const char*, const char*> typeAndIcon(ClientWarden::CipherType type) {
        switch (type) {
            case ClientWarden::CipherType::Card: return { "Card", "CreditCard" };
            case ClientWarden::CipherType::Identity: return { "Identity", "IdCard" };
            case ClientWarden::CipherType::Note: return { "Note", "StickyNote" };
            case ClientWarden::CipherType::SSHKey: return { "SSHKey", "KeyRound" };
            case ClientWarden::CipherType::Login: return { "Login", "Globe" };
            default: return { "Login", "SquareDashed" };
        }
    }

    jobject getItems(JNIEnv* env, const std::vector<ClientWarden::ItemSummary>& ciphers) {
        jclass itemClass = env->FindClass("com/ct5/clientwarden/ItemElement");
        if (itemClass == nullptr) {
            env->ExceptionClear();
            return makeItemList(env, {});
        }

        jmethodID constructor = env->GetMethodID(itemClass, "<init>",
            "(Ljava/util/UUID;Ljava/lang/String;Lcom/ct5/clientwarden/ItemType;Landroidx/compose/ui/graphics/vector/ImageVector;)V");

        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
        std::vector<jobject> items;

        for (const auto& cipher : ciphers) {
            std::optional<ClientWarden::Item> item = v_inst.GetItem(cipher.id);
            if (!item) {
                continue;
            }

            /*
             * ItemElement.icon is an ImageVector, so downloaded favicons
             * can't be shown yet; every item gets its type's Lucide icon.
            */
            auto [typeName, iconName] = typeAndIcon(cipher.type);

            jobject uuid = makeUuid(env, cipher.id);
            jstring name = env->NewStringUTF(item->Name().c_str());
            jobject type = getItemType(env, typeName);
            jobject icon = getLucideIcon(env, iconName);

            items.push_back(env->NewObject(itemClass, constructor, uuid, name, type, icon));

            env->DeleteLocalRef(uuid);
            env->DeleteLocalRef(name);
            env->DeleteLocalRef(type);
            env->DeleteLocalRef(icon);
        }

        env->DeleteLocalRef(itemClass);
        return makeItemList(env, items);
    }
}

extern "C" JNIEXPORT jobject JNICALL
Java_com_ct5_clientwarden_UIBridge_cb_1allItems(JNIEnv* env, jobject _this) {
    try {
        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
        return getItems(env, v_inst.Query().NotInBin().NotArchived().Run());
    } catch (...) {
        /*
         * TODO: Add TOAST
        */
        return makeItemList(env, {});
    }
}
