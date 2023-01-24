> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| OK | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCallCreateCallCodeTest/createInitFailStackUnderflow.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailStackUnderflow.json \
	cargo run --release \
	-- \
	statetest
```

> Execution Trace

```
2023-01-23T12:07:39.755495Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailStackUnderflow.json", Total Files :: 1
2023-01-23T12:07:39.755756Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailStackUnderflow.json"
2023-01-23T12:07:39.784516Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T12:07:39.784735Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T12:07:39.784738Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T12:07:39.784798Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T12:07:39.784870Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T12:07:39.784873Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailStackUnderflow"::Istanbul::0
2023-01-23T12:07:39.784876Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailStackUnderflow.json"
2023-01-23T12:07:39.784879Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:07:39.784881Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-23T12:07:40.422715Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14368922,
    events_root: None,
}
2023-01-23T12:07:40.422745Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T12:07:40.422753Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailStackUnderflow"::Berlin::0
2023-01-23T12:07:40.422756Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailStackUnderflow.json"
2023-01-23T12:07:40.422759Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:07:40.422761Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:07:40.422863Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-23T12:07:40.422870Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T12:07:40.422873Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailStackUnderflow"::London::0
2023-01-23T12:07:40.422875Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailStackUnderflow.json"
2023-01-23T12:07:40.422878Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:07:40.422879Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:07:40.422948Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-23T12:07:40.422955Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T12:07:40.422957Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailStackUnderflow"::Merge::0
2023-01-23T12:07:40.422960Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailStackUnderflow.json"
2023-01-23T12:07:40.422962Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:07:40.422964Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:07:40.423030Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-23T12:07:40.424806Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailStackUnderflow.json"
2023-01-23T12:07:40.424945Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:638.524066ms
```
