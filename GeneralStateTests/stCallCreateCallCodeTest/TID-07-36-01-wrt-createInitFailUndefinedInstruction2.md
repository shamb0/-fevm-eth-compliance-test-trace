> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| OK | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCallCreateCallCodeTest/createInitFailUndefinedInstruction2.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailUndefinedInstruction2.json \
	cargo run --release \
	-- \
	statetest
```

> Execution Trace

```
2023-01-23T12:14:14.948713Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailUndefinedInstruction2.json", Total Files :: 1
2023-01-23T12:14:14.948934Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailUndefinedInstruction2.json"
2023-01-23T12:14:14.982203Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T12:14:14.982409Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T12:14:14.982413Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T12:14:14.982466Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T12:14:14.982538Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T12:14:14.982542Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailUndefinedInstruction2"::Istanbul::0
2023-01-23T12:14:14.982545Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailUndefinedInstruction2.json"
2023-01-23T12:14:14.982548Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:14:14.982550Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-23T12:14:15.604285Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14368926,
    events_root: None,
}
2023-01-23T12:14:15.604313Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T12:14:15.604320Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailUndefinedInstruction2"::Berlin::0
2023-01-23T12:14:15.604323Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailUndefinedInstruction2.json"
2023-01-23T12:14:15.604327Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:14:15.604329Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:14:15.604423Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-23T12:14:15.604429Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T12:14:15.604431Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailUndefinedInstruction2"::London::0
2023-01-23T12:14:15.604433Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailUndefinedInstruction2.json"
2023-01-23T12:14:15.604436Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:14:15.604437Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:14:15.604498Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-23T12:14:15.604503Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T12:14:15.604505Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailUndefinedInstruction2"::Merge::0
2023-01-23T12:14:15.604507Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailUndefinedInstruction2.json"
2023-01-23T12:14:15.604510Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:14:15.604511Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:14:15.604570Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-23T12:14:15.606058Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailUndefinedInstruction2.json"
2023-01-23T12:14:15.606181Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:622.375907ms
```