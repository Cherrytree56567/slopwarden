# The desktop library behind the Rust/iced UI (Linux, Windows): the vault core plus the
# JSON bridge behind a C API (src/Platforms/Shared/CApi/cw_api.h).
function(cw_desktop_library _target _root)
    target_sources(${_target} PRIVATE
        ${_root}/src/Platforms/Shared/CApi/cw_api.cpp
        ${_root}/src/Platforms/Shared/JsonBridge/JsonBridge.cpp
        ${_root}/src/Platforms/Shared/JsonBridge/JsonBridgeShared.cpp
    )
    target_include_directories(${_target} PRIVATE ${_root}/src/Platforms/Shared)
    target_link_libraries(${_target} PRIVATE clientwarden_core_runtime)
    # Only the C API is exported: the static OpenSSL, Botan and Boost inside would otherwise
    # clash with other copies loaded into the same process.
    set_target_properties(${_target} PROPERTIES CXX_VISIBILITY_PRESET hidden VISIBILITY_INLINES_HIDDEN ON)
    if (APPLE)
        target_link_options(${_target} PRIVATE "-Wl,-exported_symbol,_cw_*")
    elseif (MINGW)
        target_link_options(${_target} PRIVATE -Wl,--exclude-all-symbols -static)
    elseif (UNIX)
        target_link_options(${_target} PRIVATE -Wl,--exclude-libs,ALL -Wl,--gc-sections)
    endif()
endfunction()
