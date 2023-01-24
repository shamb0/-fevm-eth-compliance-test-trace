> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| OK | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_SuicideEnd.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_SuicideEnd.json \
	cargo run --release \
	-- \
	statetest
```

> Execution Trace

```
2023-01-23T12:39:33.503266Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_SuicideEnd.json", Total Files :: 1
2023-01-23T12:39:33.503515Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_SuicideEnd.json"
2023-01-23T12:39:33.532984Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T12:39:33.533191Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T12:39:33.533195Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T12:39:33.533250Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T12:39:33.533253Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-23T12:39:33.533313Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T12:39:33.533315Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-23T12:39:33.533371Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T12:39:33.533374Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-23T12:39:33.533427Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T12:39:33.533500Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T12:39:33.533504Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_SuicideEnd"::Istanbul::0
2023-01-23T12:39:33.533507Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_SuicideEnd.json"
2023-01-23T12:39:33.533511Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:39:33.533512Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:39:33.890574Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-23T12:39:33.890597Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T12:39:33.890603Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_SuicideEnd"::Berlin::0
2023-01-23T12:39:33.890606Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_SuicideEnd.json"
2023-01-23T12:39:33.890609Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:39:33.890610Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:39:33.890806Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-23T12:39:33.890816Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T12:39:33.890819Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_SuicideEnd"::London::0
2023-01-23T12:39:33.890822Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_SuicideEnd.json"
2023-01-23T12:39:33.890825Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:39:33.890826Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:39:33.891005Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-23T12:39:33.891014Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T12:39:33.891017Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_SuicideEnd"::Merge::0
2023-01-23T12:39:33.891020Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_SuicideEnd.json"
2023-01-23T12:39:33.891024Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:39:33.891025Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:39:33.891201Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-23T12:39:33.892764Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_SuicideEnd.json"
2023-01-23T12:39:33.892898Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:358.231398ms
```