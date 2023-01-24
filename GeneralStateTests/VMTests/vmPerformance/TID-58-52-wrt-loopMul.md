> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/VMTests/vmPerformance/loopMul.json#L168

> For Review

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopMul.json \
	cargo run --release \
	-- \
	statetest
```

> Execution Trace

```
  Finished release [optimized] target(s) in 0.20s
     Running `target/release/evm_eth_compliance statetest`
2023-01-24T06:25:42.631062Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopMul.json", Total Files :: 1
2023-01-24T06:25:42.631289Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopMul.json"
2023-01-24T06:25:42.659382Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T06:25:42.659580Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:25:42.659585Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T06:25:42.659645Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T06:25:42.659716Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T06:25:42.659721Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "loopMul"::Istanbul::0
2023-01-24T06:25:42.659725Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/VMTests/vmPerformance/loopMul.json"
2023-01-24T06:25:42.659730Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-24T06:25:42.659734Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
```