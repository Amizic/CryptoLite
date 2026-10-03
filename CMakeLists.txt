cmake_minimum_required(VERSION 3.16)

project(ObsidianGuardLite
    VERSION 1.0.0
    DESCRIPTION "Simple Windows C++ wrapper library for OpenSSL (AES-256, RSA-4096, Post-Quantum ML-KEM-768)"
    LANGUAGES CXX)

# --- options ----------------------------------------------------------------
# BUILD_SHARED_LIBS is a standard CMake switch:
#   OFF (default) -> build a static library  (libObsidianGuardLite.a / ObsidianGuardLite.lib)
#   ON            -> build a shared library  (ObsidianGuardLite.dll)
option(BUILD_SHARED_LIBS "Build ObsidianGuardLite as a shared library instead of static" OFF)
option(OBSIDIAN_GUARD_LITE_BUILD_TESTS "Build the unit tests" ON)

# --- compiler settings ------------------------------------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# --- OpenSSL ----------------------------------------------------------------
# ML-KEM (used by the PostQuantum class) needs OpenSSL 3.5.0 or newer.
find_package(OpenSSL 3.5 REQUIRED)

# --- library ----------------------------------------------------------------
add_library(ObsidianGuardLite
    src/Aes256.cpp
    src/Rsa4096.cpp
    src/PostQuantum.cpp
)
add_library(ObsidianGuardLite::ObsidianGuardLite ALIAS ObsidianGuardLite)

target_include_directories(ObsidianGuardLite
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(ObsidianGuardLite PUBLIC OpenSSL::Crypto)

if(MINGW)
    # A static MinGW OpenSSL links against these Windows system libraries
    # (Winsock for BIO sockets, CryptoAPI for the capi/winstore stores).
    target_link_libraries(ObsidianGuardLite PUBLIC ws2_32 gdi32 crypt32)
endif()

if(BUILD_SHARED_LIBS)
    target_compile_definitions(ObsidianGuardLite PRIVATE OBSIDIAN_GUARD_LITE_EXPORTS)
else()
    target_compile_definitions(ObsidianGuardLite PUBLIC OBSIDIAN_GUARD_LITE_STATIC)
endif()

if(MSVC)
    target_compile_options(ObsidianGuardLite PRIVATE /W4)
else()
    target_compile_options(ObsidianGuardLite PRIVATE -Wall -Wextra)
endif()

# --- installation -----------------------------------------------------------
include(GNUInstallDirs)
install(TARGETS ObsidianGuardLite
    EXPORT ObsidianGuardLiteTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# --- tests ------------------------------------------------------------------
if(OBSIDIAN_GUARD_LITE_BUILD_TESTS)
    enable_testing()
    add_executable(ObsidianGuardLite_tests tests/test_main.cpp)
    target_link_libraries(ObsidianGuardLite_tests PRIVATE ObsidianGuardLite::ObsidianGuardLite)

    if(MINGW)
        # Copy the MinGW runtime DLLs next to the test executable so it runs
        # without extra PATH configuration.
        get_filename_component(_OBSIDIAN_GUARD_LITE_MINGW_BIN_DIR "${CMAKE_CXX_COMPILER}" DIRECTORY)
        set(_OBSIDIAN_GUARD_LITE_MINGW_RUNTIME_DLLS)
        foreach(_runtimeDll IN ITEMS libstdc++-6.dll libgcc_s_seh-1.dll libwinpthread-1.dll)
            if(EXISTS "${_OBSIDIAN_GUARD_LITE_MINGW_BIN_DIR}/${_runtimeDll}")
                list(APPEND _OBSIDIAN_GUARD_LITE_MINGW_RUNTIME_DLLS "${_OBSIDIAN_GUARD_LITE_MINGW_BIN_DIR}/${_runtimeDll}")
            endif()
        endforeach()
        if(_OBSIDIAN_GUARD_LITE_MINGW_RUNTIME_DLLS)
            add_custom_command(TARGET ObsidianGuardLite_tests POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different ${_OBSIDIAN_GUARD_LITE_MINGW_RUNTIME_DLLS}
                        $<TARGET_FILE_DIR:ObsidianGuardLite_tests>
                COMMENT "Copying MinGW runtime DLLs next to ObsidianGuardLite_tests")
        endif()
    endif()

    add_test(NAME ObsidianGuardLite_tests COMMAND ObsidianGuardLite_tests)
    # RSA-4096 key generation is intentionally slow; be generous on CI.
    # The test binary pauses at the end when run interactively; disable the
    # pause under CTest so automated runs never wait for a keypress.
    set_tests_properties(ObsidianGuardLite_tests PROPERTIES
        TIMEOUT 600
        ENVIRONMENT "OBSIDIAN_GUARD_NO_PAUSE=1"
    )
endif()
