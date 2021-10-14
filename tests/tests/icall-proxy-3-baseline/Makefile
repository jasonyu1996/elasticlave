.PHONY: all build clean


RECORD_SIZE:=512 1024 2048 4096 8192 16384 32768 65536
TEST_NAME:=icall-proxy-3-baseline

build/$(TEST_NAME).sh: build 
	mkdir -p build
	mkdir -p build_pack
	cp enclaves/$(TEST_NAME)*.eapp_riscv build_pack/
	cp host/$(TEST_NAME).riscv build_pack/
	cp $(RUNTIME_FILE) build_pack/
	cat /dev/null > build_pack/run_test
	$(foreach vn,$(RECORD_SIZE),\
		echo "./$(TEST_NAME).riscv $(vn)" >> build_pack/run_test; \
	)
	chmod +x build_pack/run_test
	makeself --noprogress build_pack $@ "Micro-benchmark $(TEST_NAME)" "./run_test"
	chmod +x $@

build:
	$(MAKE) -C enclaves
	$(MAKE) -C host


clean:
	$(MAKE) -C enclaves clean
	$(MAKE) -C host clean
	rm -rf build/$(TEST_NAME).sh



