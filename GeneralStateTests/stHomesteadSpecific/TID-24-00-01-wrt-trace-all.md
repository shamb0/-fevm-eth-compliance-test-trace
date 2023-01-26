> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stHomesteadSpecific

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stHomesteadSpecific \
	cargo run --release \
	-- \
	statetest
```

> For Review

* Following use-case are skipped due to `transaction.tx` empty. Have to re-check on revm

| Test ID | Use-Case |
| --- | --- |
| TID-24-02 | contractCreationOOGdontLeaveEmptyContractViaTransaction |
| TID-24-05 | createContractViaTransactionCost53000 |
