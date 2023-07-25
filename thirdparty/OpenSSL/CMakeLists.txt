# check if wxWidgets is already installed in the system - using CMake's built in script FindOpenSSL
find_package(OpenSSL QUIET)

if(OPENSSL_FOUND)
	message(STATUS "Found preinstalled OpenSSL libraries at ${OPENSSL_LIBRARIES}")
	add_library(OpenSSL_external INTERFACE)
else()
	message(STATUS "Preinstalled OpenSSL library not found")
	message(STATUS "Will now download and install OpenSLL in ${STAGED_INSTALL_PREFIX}")

	include(ExternalProject)
	ExternalProject_Add(OpenSSL_external
		GIT_REPOSITORY
		https://github.com/openssl/openssl.git 
		GIT_TAG 
		OpenSSL_1_1_1u  
		UPDATE_COMMAND 
		"" 
		CMAKE_ARGS 
		-DCMAKE_INSTALL_PREFIX=${STAGE_INSTALL_PREFIX} 
		-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} 
	 
		TEST_AFTER_INSTALL 
		0 
		DOWNLOAD_NO_PROGRESS 
        1 
        LOG_CONFIGURE 
        1 
        LOG_BUILD 
        1 
        LOG_INSTALL 
        1 
	)

	set(OPENSSL_ROOT_DIR ${STAGED_INSTALL_PREFIX})
	file(TO_NATIVE_PATH "${OPENSSL_ROOT_DIR}" OPENSSL_ROOT_DIR)
	set(OPENSSL_ROOT_DIR ${OPENSSL_ROOT_DIR} CACHE INTERNAL "OpenSLL installation dir")

endif()