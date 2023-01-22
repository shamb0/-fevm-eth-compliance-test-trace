> Status

| Status | Context |
| --- | --- |
| KO | under WASM RT context |
| OK | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCallCodes/callcall_00_SuicideEnd.json#L15

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCallCodes/callcall_00_SuicideEnd.json \
	cargo run \
	-- \
	statetest
```

> Execution Trace

```

```