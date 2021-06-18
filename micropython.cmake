add_library(usermod_hydrogen INTERFACE)

target_sources(usermod_hydrogen INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}/hydrogen.c
)

target_include_directories(usermod_hydrogen INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}
)

target_link_libraries(usermod INTERFACE usermod_hydrogen)
