> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| OK | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcode_11_SuicideEnd.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcode_11_SuicideEnd.json \
	cargo run --release \
	-- \
	statetest
```

> Execution Trace

```
2023-01-23T12:35:44.300299Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcode_11_SuicideEnd.json", Total Files :: 1
2023-01-23T12:35:44.300570Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcode_11_SuicideEnd.json"
2023-01-23T12:35:44.330202Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T12:35:44.330397Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T12:35:44.330401Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T12:35:44.330452Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T12:35:44.330454Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-23T12:35:44.330511Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T12:35:44.330513Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-23T12:35:44.330566Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T12:35:44.330635Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T12:35:44.330638Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11_SuicideEnd"::Istanbul::0
2023-01-23T12:35:44.330641Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcode_11_SuicideEnd.json"
2023-01-23T12:35:44.330644Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:35:44.330645Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:35:44.698253Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-23T12:35:44.698277Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T12:35:44.698284Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11_SuicideEnd"::Berlin::0
2023-01-23T12:35:44.698287Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcode_11_SuicideEnd.json"
2023-01-23T12:35:44.698290Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:35:44.698292Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:35:44.698481Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-23T12:35:44.698490Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T12:35:44.698493Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11_SuicideEnd"::London::0
2023-01-23T12:35:44.698496Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcode_11_SuicideEnd.json"
2023-01-23T12:35:44.698500Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:35:44.698501Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:35:44.698673Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-23T12:35:44.698683Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T12:35:44.698685Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11_SuicideEnd"::Merge::0
2023-01-23T12:35:44.698687Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcode_11_SuicideEnd.json"
2023-01-23T12:35:44.698690Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:35:44.698692Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:35:44.698867Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-23T12:35:44.700433Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcode_11_SuicideEnd.json"
2023-01-23T12:35:44.700547Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:368.678073ms
```