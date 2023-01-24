> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| OK | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecall_10_SuicideEnd.json#L1


> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecall_10_SuicideEnd.json \
	cargo run --release \
	-- \
	statetest
```

> Execution Trace

```
2023-01-23T12:23:52.249051Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecall_10_SuicideEnd.json", Total Files :: 1
2023-01-23T12:23:52.249299Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecall_10_SuicideEnd.json"
2023-01-23T12:23:52.278182Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T12:23:52.278382Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T12:23:52.278385Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T12:23:52.278437Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T12:23:52.278439Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-23T12:23:52.278498Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T12:23:52.278500Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-23T12:23:52.278555Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T12:23:52.278625Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T12:23:52.278629Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10_SuicideEnd"::Istanbul::0
2023-01-23T12:23:52.278631Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecall_10_SuicideEnd.json"
2023-01-23T12:23:52.278635Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:23:52.278636Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:23:52.627351Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-23T12:23:52.627372Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T12:23:52.627380Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10_SuicideEnd"::Berlin::0
2023-01-23T12:23:52.627382Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecall_10_SuicideEnd.json"
2023-01-23T12:23:52.627385Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:23:52.627387Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:23:52.627571Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-23T12:23:52.627581Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T12:23:52.627583Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10_SuicideEnd"::London::0
2023-01-23T12:23:52.627586Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecall_10_SuicideEnd.json"
2023-01-23T12:23:52.627589Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:23:52.627590Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:23:52.627759Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-23T12:23:52.627768Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T12:23:52.627771Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10_SuicideEnd"::Merge::0
2023-01-23T12:23:52.627774Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecall_10_SuicideEnd.json"
2023-01-23T12:23:52.627777Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:23:52.627778Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:23:52.627982Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-23T12:23:52.629530Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecall_10_SuicideEnd.json"
2023-01-23T12:23:52.629643Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:349.813817ms
```