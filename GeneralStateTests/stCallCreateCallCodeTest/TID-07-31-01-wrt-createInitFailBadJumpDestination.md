> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| OK | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCallCreateCallCodeTest/createInitFailBadJumpDestination.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailBadJumpDestination.json \
	cargo run --release \
	-- \
	statetest
```

> Execution Trace

```
2023-01-23T11:34:52.815352Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailBadJumpDestination.json", Total Files :: 1
2023-01-23T11:34:52.815568Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailBadJumpDestination.json"
2023-01-23T11:34:52.843666Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T11:34:52.843885Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T11:34:52.843890Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T11:34:52.843945Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T11:34:52.844028Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T11:34:52.844032Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailBadJumpDestination"::Istanbul::0
2023-01-23T11:34:52.844035Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailBadJumpDestination.json"
2023-01-23T11:34:52.844039Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T11:34:52.844040Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-23T11:34:53.479298Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14368910,
    events_root: None,
}
2023-01-23T11:34:53.479330Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T11:34:53.479337Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailBadJumpDestination"::Berlin::0
2023-01-23T11:34:53.479339Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailBadJumpDestination.json"
2023-01-23T11:34:53.479343Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T11:34:53.479344Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T11:34:53.479444Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-23T11:34:53.479450Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T11:34:53.479453Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailBadJumpDestination"::London::0
2023-01-23T11:34:53.479455Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailBadJumpDestination.json"
2023-01-23T11:34:53.479458Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T11:34:53.479459Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T11:34:53.479525Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-23T11:34:53.479531Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T11:34:53.479534Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailBadJumpDestination"::Merge::0
2023-01-23T11:34:53.479536Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailBadJumpDestination.json"
2023-01-23T11:34:53.479539Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T11:34:53.479540Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T11:34:53.479605Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-23T11:34:53.481704Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailBadJumpDestination.json"
2023-01-23T11:34:53.481856Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:635.948651ms
```