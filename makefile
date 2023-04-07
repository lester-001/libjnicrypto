GREEN=\033[0;1;92m
NC=\033[0m

build: FORCE
	rm -fr logs # Old version log files
	mkdir -p build
	rm -fr build/*
	
	# cmake -DCMAKE_BUILD_TYPE=Debug -G "CodeBlocks - Unix Makefiles" . -B cmake-build-debug
	cmake -DCMAKE_BUILD_TYPE=Release -G "CodeBlocks - Unix Makefiles" . -B cmake-build-release
	# cmake --build cmake-build-debug --target all
	cmake --build cmake-build-release --target all
	
	cp cmake-build-release/src/jnicrypto/libjnicrypto.so build/

	@printf "${GREEN}UERANSIM successfully built.${NC}\n"

FORCE:
