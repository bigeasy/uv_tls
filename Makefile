all: ./build submake

./build: ./deps/gyp
	gyp uv_tls.gyp --depth=. -f make --generator-output=./build

submake:
	make -C ./build

test: ./build/out/Release/uv_tls_test
	./build/out/Release/uv_tls_test

clean:
	rm -rf ./build
	rm -rf ./out


.PHONY: test submake
