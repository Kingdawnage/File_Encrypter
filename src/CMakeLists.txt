cmake_minimum_required(VERSION 3.6 FATAL_ERROR)

project(File_Encrypter_core LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(OPENSSL_USE_STATIC_LIB TRUE)

find_package(OpenSSL REQUIRED)

set(SRCS main.cpp)

if(APPLE)
	# create bundle on apple compiles
	add_executable(main MACOSX_BUNDLE ${SRCS})

	# set custom plist file for the app bundle - needed for Mac OS Retina display
	set_target_properties(main PROPERTIES MACOSX_BUNDLE_INFO_PLIST ${CMAKE_CURRENT_SOURCE_DIR}/Info.plist)
else()
	# the WIN32 is needed for Windows in order for it to look for WinMain
    # instead of the main function. This is ignored on other systems,
    # so it works on all platforms
	add_executable(main WIN32 ${SRCS} main.exe.manifest)
endif()

target_link_libraries(main ${OPENSSL_LIBRARIES})