> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| OK | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCallCodes/callcallcode_01_SuicideEnd.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCallCodes/callcallcode_01_SuicideEnd.json \
	cargo run --release \
	-- \
	statetest
```

> Execution Trace

```
2023-01-23T11:26:30.875316Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stCallCodes/callcallcode_01_SuicideEnd.json", Total Files :: 1
2023-01-23T11:26:30.875568Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stCallCodes/callcallcode_01_SuicideEnd.json"
2023-01-23T11:26:30.904197Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T11:26:30.904426Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T11:26:30.904430Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T11:26:30.904484Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T11:26:30.904486Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-23T11:26:30.904544Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T11:26:30.904546Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-23T11:26:30.904601Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T11:26:30.904672Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T11:26:30.904676Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01_SuicideEnd"::Istanbul::0
2023-01-23T11:26:30.904679Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCodes/callcallcode_01_SuicideEnd.json"
2023-01-23T11:26:30.904682Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T11:26:30.904683Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T11:26:31.252499Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-23T11:26:31.252523Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T11:26:31.252533Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01_SuicideEnd"::Berlin::0
2023-01-23T11:26:31.252536Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCodes/callcallcode_01_SuicideEnd.json"
2023-01-23T11:26:31.252540Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T11:26:31.252541Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T11:26:31.252667Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-23T11:26:31.252675Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T11:26:31.252678Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01_SuicideEnd"::London::0
2023-01-23T11:26:31.252680Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCodes/callcallcode_01_SuicideEnd.json"
2023-01-23T11:26:31.252683Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T11:26:31.252684Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T11:26:31.252799Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-23T11:26:31.252808Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T11:26:31.252811Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01_SuicideEnd"::Merge::0
2023-01-23T11:26:31.252813Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCodes/callcallcode_01_SuicideEnd.json"
2023-01-23T11:26:31.252816Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T11:26:31.252817Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T11:26:31.252943Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-23T11:26:31.254307Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stCallCodes/callcallcode_01_SuicideEnd.json"
2023-01-23T11:26:31.254440Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:348.758099ms
```