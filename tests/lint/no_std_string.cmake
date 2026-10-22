# Fails if any vault core source mentions std::string (ADR 3), except the files that wrap
# third-party APIs which only speak std::string. Those convert to SecureString immediately and
# wipe their temporaries; each carries a comment explaining why it is allowlisted.

set(ALLOWLIST
    platform/http/httplib_transport.cpp     # cpp-httplib API
    platform/secret_store/keychain_secret_store.cpp  # keychain library API
)

get_filename_component(CORE_DIR "${CORE_DIR}" ABSOLUTE)
file(GLOB_RECURSE SOURCES "${CORE_DIR}/*.h" "${CORE_DIR}/*.cpp")
set(VIOLATIONS "")
foreach(SOURCE ${SOURCES})
    file(RELATIVE_PATH RELATIVE "${CORE_DIR}" "${SOURCE}")
    list(FIND ALLOWLIST "${RELATIVE}" ALLOWED)
    if (NOT ALLOWED EQUAL -1)
        continue()
    endif()

    file(STRINGS "${SOURCE}" LINES REGEX "std::(w|u8|u16|u32)?string([^_a-zA-Z0-9]|$)")
    foreach(LINE ${LINES})
        string(STRIP "${LINE}" LINE)
        list(APPEND VIOLATIONS "${RELATIVE}: ${LINE}")
    endforeach()
endforeach()

if (VIOLATIONS)
    list(JOIN VIOLATIONS "\n  " REPORT)
    message(FATAL_ERROR "std::string used in the vault core (use SecureString):\n  ${REPORT}")
endif()
message(STATUS "No std::string in the vault core")
