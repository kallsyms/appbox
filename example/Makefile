CODESIGN := codesign
CARGO := cargo +nightly

TARGET := example

.PHONY: build-debug
build-debug:
	$(CARGO) build
	$(CODESIGN) --entitlements entitlements.xml --force -s - target/debug/$(TARGET)
