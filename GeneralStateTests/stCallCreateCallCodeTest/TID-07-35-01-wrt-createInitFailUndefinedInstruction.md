> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| OK | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCallCreateCallCodeTest/createInitFailUndefinedInstruction.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailUndefinedInstruction.json \
	cargo run --release \
	-- \
	statetest
```

> Execution Trace

```
2023-01-23T12:11:04.397521Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailUndefinedInstruction.json", Total Files :: 1
2023-01-23T12:11:04.397762Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailUndefinedInstruction.json"
2023-01-23T12:11:04.425959Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T12:11:04.426172Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T12:11:04.426176Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T12:11:04.426229Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T12:11:04.426231Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-23T12:11:04.426288Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T12:11:04.426290Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-23T12:11:04.426344Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T12:11:04.426414Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T12:11:04.426418Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailUndefinedInstruction"::Istanbul::0
2023-01-23T12:11:04.426421Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailUndefinedInstruction.json"
2023-01-23T12:11:04.426424Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:11:04.426426Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:11:04.803172Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3620865,
    events_root: None,
}
2023-01-23T12:11:04.803194Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T12:11:04.803202Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailUndefinedInstruction"::Berlin::0
2023-01-23T12:11:04.803204Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailUndefinedInstruction.json"
2023-01-23T12:11:04.803207Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:11:04.803208Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:11:04.803353Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2723402,
    events_root: None,
}
2023-01-23T12:11:04.803361Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T12:11:04.803363Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailUndefinedInstruction"::London::0
2023-01-23T12:11:04.803366Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailUndefinedInstruction.json"
2023-01-23T12:11:04.803368Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:11:04.803370Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:11:04.803496Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2723402,
    events_root: None,
}
2023-01-23T12:11:04.803504Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T12:11:04.803507Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailUndefinedInstruction"::Merge::0
2023-01-23T12:11:04.803510Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailUndefinedInstruction.json"
2023-01-23T12:11:04.803512Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:11:04.803514Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:11:04.803639Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2723402,
    events_root: None,
}
2023-01-23T12:11:04.805263Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailUndefinedInstruction.json"
2023-01-23T12:11:04.805409Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:377.693379ms
```