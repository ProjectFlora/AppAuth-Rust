cmake_minimum_required(VERSION 3.20)
project(appauth_release_consumer LANGUAGES CXX)

if(NOT DEFINED APPAUTH_PACKAGE)
    message(FATAL_ERROR "APPAUTH_PACKAGE must point to the extracted Windows release package")
endif()

add_executable(appauth_release_consumer main.cpp)
target_compile_features(appauth_release_consumer PRIVATE cxx_std_17)
target_include_directories(appauth_release_consumer PRIVATE "${APPAUTH_PACKAGE}/include")
target_link_libraries(appauth_release_consumer PRIVATE "${APPAUTH_PACKAGE}/appauth_rust.dll.lib")
add_custom_command(TARGET appauth_release_consumer POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${APPAUTH_PACKAGE}/appauth_rust.dll"
        "$<TARGET_FILE_DIR:appauth_release_consumer>/appauth_rust.dll")
