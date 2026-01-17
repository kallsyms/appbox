CODESIGN := codesign
CARGO := cargo
ARGS ?=

.PHONY: build
build:
	$(CARGO) build

# Build --release for performance
.PHONY: example-%
example-%:
	$(CARGO) build --example $* --release  
	$(CODESIGN) --entitlements examples/entitlements.xml --force -s - target/release/examples/$*
	RUST_BACKTRACE=1 RUST_LOG=info target/release/examples/$* $(ARGS)
