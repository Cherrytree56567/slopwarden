include(cmake/versioning.cmake)

# Builds libclientwarden.so (the vault core plus the JNI binding the Kotlin UI calls) into the
# app's jniLibs, then the APK with Gradle.
function(buildUI _target)
    if (WIN32)
        set(GRADLE_RUN ${CMAKE_CURRENT_SOURCE_DIR}/src/Platforms/Android/UI/gradlew.bat)
    else()
        set(GRADLE_RUN ${CMAKE_CURRENT_SOURCE_DIR}/src/Platforms/Android/UI/gradlew)
    endif()

    add_custom_target(UI ALL
        COMMAND ${GRADLE_RUN} :app:assembleDebug
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/Platforms/Android/UI/
        COMMENT "Building Android UI through GradleW"
    )

    target_sources(${_target} PRIVATE
        src/Platforms/Android/Native/Jni.cpp
        src/Platforms/Android/Native/Native.cpp
        src/Platforms/Android/Native/AndroidSecretStore.cpp
        src/Platforms/Shared/JsonBridge/JsonBridge.cpp
        src/Platforms/Shared/JsonBridge/JsonBridgeShared.cpp
    )

    target_include_directories(${_target} PRIVATE src/Platforms/Android/ src/Platforms/Shared/)
    target_link_libraries(${_target} PRIVATE log)

    if (ANDROID)
        set_target_properties(${_target} PROPERTIES
            LIBRARY_OUTPUT_DIRECTORY
            ${CMAKE_CURRENT_SOURCE_DIR}/src/Platforms/Android/UI/app/src/main/jniLibs/${ANDROID_ABI}
        )
        # Keep the JNI entry points; hide everything else.
        # 16 KB pages are required on Android 15+ devices.
        target_link_options(${_target} PRIVATE -Wl,--exclude-libs,ALL -Wl,--gc-sections -Wl,-z,max-page-size=16384)
    endif()

    add_dependencies(UI ${_target})
endfunction()
