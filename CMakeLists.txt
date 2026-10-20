cmake_minimum_required(VERSION 3.16)
project(profmig VERSION 1.0.0 LANGUAGES CXX RC)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# El recurso (version del .exe + manifiesto) se genera con la version del proyecto
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/profmig.rc.in ${CMAKE_BINARY_DIR}/profmig.rc @ONLY)

add_executable(profmig WIN32
    src/main.cpp
    src/gui.cpp
    src/migrate.cpp
    src/transfer.cpp
    src/journal.cpp
    src/ldap.cpp
    src/util.cpp
    src/sid.cpp
    src/regops.cpp
    src/fsops.cpp
    src/secops.cpp
    src/ucpd.cpp
    ${CMAKE_BINARY_DIR}/profmig.rc)

target_compile_definitions(profmig PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00
                                           SECURITY_WIN32 PROFMIG_VERSION="${PROJECT_VERSION}")
target_link_libraries(profmig PRIVATE advapi32 netapi32 mpr shell32 ole32 wldap32 comctl32 comdlg32 user32 gdi32)

if(MSVC)
    target_compile_options(profmig PRIVATE /W4 /utf-8)
    set_property(TARGET profmig PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
else()
    target_compile_options(profmig PRIVATE -Wall -Wextra)
    target_link_options(profmig PRIVATE -static)
    # Quitar los simbolos reduce el tamano a la mitad, pero a algunos antivirus (heuristicas) no les gustan los
    # ejecutables sin simbolos: por defecto NO se quitan.
    option(PROFMIG_STRIP "Quitar los simbolos del ejecutable (menor tamano)" OFF)
    if(PROFMIG_STRIP)
        target_link_options(profmig PRIVATE -s)
    endif()
endif()

# Test manual de exportar/extraer (no requiere admin): cmake --build build --target transfer_test
add_executable(transfer_test EXCLUDE_FROM_ALL tests/transfer_test.cpp src/transfer.cpp src/util.cpp)
target_include_directories(transfer_test PRIVATE src)
target_compile_definitions(transfer_test PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
if(NOT MSVC)
    target_link_options(transfer_test PRIVATE -static)
endif()

# Test de la traduccion de SID (no requiere admin): cmake --build build --target secops_test
add_executable(secops_test EXCLUDE_FROM_ALL tests/secops_test.cpp src/secops.cpp src/sid.cpp src/util.cpp)
target_include_directories(secops_test PRIVATE src)
target_compile_definitions(secops_test PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(secops_test PRIVATE advapi32 mpr)
if(NOT MSVC)
    target_link_options(secops_test PRIVATE -static)
endif()
