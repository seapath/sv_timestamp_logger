cmake_minimum_required(VERSION 3.10)
project (sv_timestamp_logger C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_C_STANDARD 99)
add_compile_options(-Werror -Wall -Wextra -Wno-unused-label -Wno-unused-parameter)

if(NOT CMAKE_BUILD_TYPE)
set(CMAKE_BUILD_TYPE "Release" CACHE STRING
"Choose the type of build, options are: Debug Release RelWithDebInfo MinSizeRel."
FORCE)
endif()

option(ENABLE_ASAN "enable address sanitizer" OFF)
if (ENABLE_ASAN)
    add_compile_options(-fsanitize=address)
    add_link_options(-fsanitize=address)
endif()



option(BUILD_STATIC "Build only sv_subscriber and sv_publisher with a static linking" OFF)
option(GIVE_CAP "Give CAP_NET_RAW to generated executable" OFF)

FILE(GLOB sv_timestamp_logger_sources sv_timestamp_logger/*.c sv_timestamp_logger/.*h;)
include_directories(.)
add_executable(sv_timestamp_logger
    lib/sv_monitor.h
    lib/sv_monitor.c
    sv_timestamp_logger.h
    sv_timestamp_logger.c
    lib/sv_parser/sv_parser.c
    lib/sv_parser/sv_parser.h
)
target_link_libraries(sv_timestamp_logger pcap m)

if(BUILD_STATIC)
target_link_options(sv_timestamp_logger PRIVATE "-static")
endif(BUILD_STATIC)

install(TARGETS sv_timestamp_logger DESTINATION bin)

if(GIVE_CAP)
  add_custom_command(TARGET sv_timestamp_logger POST_BUILD
    COMMAND sudo setcap cap_net_raw+ep $<TARGET_FILE:sv_timestamp_logger>
    COMMENT "Setting CAP_NET_RAW capability on sv_timestamp_logger"
  )
endif(GIVE_CAP)
