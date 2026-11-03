cmake_minimum_required(VERSION 3.16)

# Development release identity. ESP-IDF embeds PROJECT_VER in esp_app_desc_t,
# which is used by the OTA manager for current/previous firmware reporting.
set(PROJECT_VER "3.1.12")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

project(esp32p4_nts_time_server)