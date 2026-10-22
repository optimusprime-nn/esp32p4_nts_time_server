cmake_minimum_required(VERSION 3.16)

# Standalone Unity test app for main/nts_aes_siv.c. It builds the source file
# directly rather than the whole firmware component, so it needs no hardware
# beyond an ESP32-P4 to run the tests on.
include($ENV{IDF_PATH}/tools/cmake/project.cmake)

project(nts_aes_siv_test_app)
