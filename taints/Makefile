.SECONDARY:

meson=meson
ninja=ninja
llvmconfig=$(shell which llvm-config)

PWD=$(shell pwd)

pullup:
	git pull --rebase origin bjrn_pdtg
	git pull --rebase origin rahul_pldi

rebuild:
	rm -rf build install
	echo "[binaries]" > multi.cross
	echo "llvm-config = '$(llvmconfig)' " >> multi.cross
	$(meson) build/debug --prefix="$(PWD)/install" --native-file multi.cross
	$(ninja) -C build/debug install

build/%.c.instrumented: build/%.c
	./install/bin/trace-instr $< ./samples/excluded_functions

build/%.run: build/%.c.instrumented
	cat build/$*.input | $<
	gzip -c output > build/output.gz

build/%.taint: build/%.run
	./install/bin/trace-taint -me build/metadata -po build/pygmalion.json -t build/output.gz

clean:
	rm -rf build/*

chain:
	cd chains; python3 chains.py -p $(abspath $(SUBJECT)) -a False -i True
