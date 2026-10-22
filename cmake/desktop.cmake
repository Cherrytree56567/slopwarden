include(cmake/versioning.cmake)
include(cmake/desktop_library.cmake)

# Linux and Windows: libclientwarden (vault core + C API), then the Rust/iced UI in
# src/Platforms/Linux linked against it. Both end up side by side in ${CMAKE_BINARY_DIR}/app.
# Cross builds set CW_CARGO_TARGET (e.g. x86_64-pc-windows-gnu).
function(buildUI _target)
    cw_desktop_library(${_target} ${CMAKE_CURRENT_SOURCE_DIR})

    set(CW_APP_DIR ${CMAKE_BINARY_DIR}/app)
    set_target_properties(${_target} PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY ${CW_APP_DIR}
        RUNTIME_OUTPUT_DIRECTORY ${CW_APP_DIR}
        ARCHIVE_OUTPUT_DIRECTORY ${CW_APP_DIR}
        PREFIX "lib"
    )

    set(CW_CARGO_DIR ${CMAKE_BINARY_DIR}/cargo)
    set(CW_CARGO_ARGS build --release --manifest-path ${CMAKE_CURRENT_SOURCE_DIR}/src/Platforms/Linux/Cargo.toml --target-dir ${CW_CARGO_DIR})
    if (CW_CARGO_TARGET)
        list(APPEND CW_CARGO_ARGS --target ${CW_CARGO_TARGET})
        set(CW_CARGO_OUT ${CW_CARGO_DIR}/${CW_CARGO_TARGET}/release)
    else()
        set(CW_CARGO_OUT ${CW_CARGO_DIR}/release)
    endif()
    # Cargo names the binary after the [[bin]] (lowercase); Windows users get ClientWarden.exe.
    # Spelled exactly: builds on case-insensitive file systems hide a mismatch.
    if (WIN32)
        set(CW_CARGO_BINARY clientwarden.exe)
        set(CW_UI_BINARY ClientWarden.exe)
    else()
        set(CW_CARGO_BINARY clientwarden)
        set(CW_UI_BINARY clientwarden)
    endif()

    add_custom_target(UI ALL
        COMMAND ${CMAKE_COMMAND} -E env CW_LIB_DIR=${CW_APP_DIR} cargo ${CW_CARGO_ARGS}
        COMMAND ${CMAKE_COMMAND} -E copy ${CW_CARGO_OUT}/${CW_CARGO_BINARY} ${CW_APP_DIR}/${CW_UI_BINARY}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/Platforms/Linux
        COMMENT "Building the iced UI with Cargo"
        USES_TERMINAL
    )
    add_dependencies(UI ${_target})
endfunction()
