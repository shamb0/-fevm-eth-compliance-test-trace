> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stEIP150Specific

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stEIP150Specific \
	cargo run --release \
	-- \
	statetest
```

> For Review

- Hit with error `EVM_CONTRACT_UNDEFINED_INSTRUCTION` (ExitCode::35)

| Test ID | Use-Case |
| --- | --- |
| TID-17-01 | CallAndCallcodeConsumeMoreGasThenTransactionHas |
| TID-17-08 | NewGasPriceForCodes |
| TID-17-14 | Transaction64Rule_integerBoundaries |
