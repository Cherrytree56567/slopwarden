#include <jni.h>
#include <string>
#include <vector>
#include "vault_manager/vault_manager.h"

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

    jobject makeUuid(JNIEnv* env, const clientwarden::SecureString& uuid) {
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
    std::pair<const char*, const char*> typeAndIcon(clientwarden::CipherType type) {
        switch (type) {
            case clientwarden::CipherType::Card: return { "Card", "CreditCard" };
            case clientwarden::CipherType::Identity: return { "Identity", "IdCard" };
            case clientwarden::CipherType::Note: return { "Note", "StickyNote" };
            case clientwarden::CipherType::SshKey: return { "SSHKey", "KeyRound" };
            case clientwarden::CipherType::Login: return { "Login", "Globe" };
            default: return { "Login", "SquareDashed" };
        }
    }

    jobject getItems(JNIEnv* env, const std::vector<clientwarden::ItemSummary>& ciphers) {
        jclass itemClass = env->FindClass("com/ct5/clientwarden/ItemElement");
        if (itemClass == nullptr) {
            env->ExceptionClear();
            return makeItemList(env, {});
        }

        jmethodID constructor = env->GetMethodID(itemClass, "<init>",
            "(Ljava/util/UUID;Ljava/lang/String;Lcom/ct5/clientwarden/ItemType;Landroidx/compose/ui/graphics/vector/ImageVector;)V");

        std::shared_ptr<clientwarden::Orchestrator> orchestrator =
            clientwarden::VaultManager::instance().getActiveVault()->getOrchestrator();
        std::vector<jobject> items;

        for (const auto& cipher : ciphers) {
            clientwarden::SecureString itemName;
            try {
                itemName = orchestrator->getGenericItem(cipher.m_id)->getName();
            } catch (const clientwarden::VaultError&) {
                continue;
            }

            /*
             * ItemElement.icon is an ImageVector, so downloaded favicons
             * can't be shown yet; every item gets its type's Lucide icon.
            */
            auto [typeName, iconName] = typeAndIcon(cipher.m_type);

            jobject uuid = makeUuid(env, cipher.m_id);
            jstring name = env->NewStringUTF(itemName.c_str());
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
        std::shared_ptr<clientwarden::Vault> vault = clientwarden::VaultManager::instance().getActiveVault();
        return getItems(env, vault->getOrchestrator()->query().notInBin().notArchived().run());
    } catch (...) {
        /*
         * TODO: Add TOAST
        */
        return makeItemList(env, {});
    }
}
