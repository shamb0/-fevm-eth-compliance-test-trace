> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| OK | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCallCreateCallCodeTest/createInitFailBadJumpDestination2.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailBadJumpDestination2.json \
	cargo run --release \
	-- \
	statetest
```

> Execution Trace

```
2023-01-23T12:01:25.348276Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailBadJumpDestination2.json", Total Files :: 1
2023-01-23T12:01:25.348488Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailBadJumpDestination2.json"
2023-01-23T12:01:25.375886Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T12:01:25.376103Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T12:01:25.376106Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T12:01:25.376160Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T12:01:25.376231Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T12:01:25.376235Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailBadJumpDestination2"::Istanbul::0
2023-01-23T12:01:25.376238Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailBadJumpDestination2.json"
2023-01-23T12:01:25.376241Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:01:25.376243Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-23T12:01:26.026701Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14375991,
    events_root: None,
}
2023-01-23T12:01:26.026736Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T12:01:26.026747Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailBadJumpDestination2"::Berlin::0
2023-01-23T12:01:26.026751Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailBadJumpDestination2.json"
2023-01-23T12:01:26.026756Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:01:26.026758Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:01:26.026893Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-23T12:01:26.026902Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T12:01:26.026906Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailBadJumpDestination2"::London::0
2023-01-23T12:01:26.026909Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailBadJumpDestination2.json"
2023-01-23T12:01:26.026914Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:01:26.026916Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:01:26.027018Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-23T12:01:26.027027Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T12:01:26.027030Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailBadJumpDestination2"::Merge::0
2023-01-23T12:01:26.027033Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailBadJumpDestination2.json"
2023-01-23T12:01:26.027038Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:01:26.027040Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:01:26.027135Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-23T12:01:26.029198Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailBadJumpDestination2.json"
2023-01-23T12:01:26.029326Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:651.262331ms
```