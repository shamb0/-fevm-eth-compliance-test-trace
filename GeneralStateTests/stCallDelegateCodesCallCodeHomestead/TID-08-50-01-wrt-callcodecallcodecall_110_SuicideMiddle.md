> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| OK | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_SuicideMiddle.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_SuicideMiddle.json \
	cargo run --release \
	-- \
	statetest
```

> Execution Trace

```
2023-01-23T12:42:58.609953Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_SuicideMiddle.json", Total Files :: 1
2023-01-23T12:42:58.610220Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_SuicideMiddle.json"
2023-01-23T12:42:58.638932Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T12:42:58.639129Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T12:42:58.639133Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T12:42:58.639186Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T12:42:58.639188Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-23T12:42:58.639247Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T12:42:58.639249Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-23T12:42:58.639302Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T12:42:58.639304Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-23T12:42:58.639356Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T12:42:58.639426Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T12:42:58.639429Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_SuicideMiddle"::Istanbul::0
2023-01-23T12:42:58.639432Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_SuicideMiddle.json"
2023-01-23T12:42:58.639436Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:42:58.639437Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:42:59.023116Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-23T12:42:59.023136Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T12:42:59.023144Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_SuicideMiddle"::Berlin::0
2023-01-23T12:42:59.023146Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_SuicideMiddle.json"
2023-01-23T12:42:59.023150Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:42:59.023151Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:42:59.023331Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-23T12:42:59.023340Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T12:42:59.023343Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_SuicideMiddle"::London::0
2023-01-23T12:42:59.023345Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_SuicideMiddle.json"
2023-01-23T12:42:59.023348Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:42:59.023350Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:42:59.023516Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-23T12:42:59.023525Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T12:42:59.023528Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_SuicideMiddle"::Merge::0
2023-01-23T12:42:59.023530Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_SuicideMiddle.json"
2023-01-23T12:42:59.023533Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:42:59.023535Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:42:59.023701Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-23T12:42:59.025290Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stCallDelegateCodesCallCodeHomestead/callcodecallcodecall_110_SuicideMiddle.json"
2023-01-23T12:42:59.025418Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:384.782652ms

```