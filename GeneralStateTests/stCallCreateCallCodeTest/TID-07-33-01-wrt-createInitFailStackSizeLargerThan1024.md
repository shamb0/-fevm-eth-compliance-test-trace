> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| OK | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCallCreateCallCodeTest/createInitFailStackSizeLargerThan1024.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailStackSizeLargerThan1024.json \
	cargo run --release \
	-- \
	statetest
```

> Execution Trace

```
2023-01-23T12:04:44.051029Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailStackSizeLargerThan1024.json", Total Files :: 1
2023-01-23T12:04:44.051266Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailStackSizeLargerThan1024.json"
2023-01-23T12:04:44.080220Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T12:04:44.080452Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T12:04:44.080456Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T12:04:44.080517Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T12:04:44.080597Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T12:04:44.080602Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailStackSizeLargerThan1024"::Istanbul::0
2023-01-23T12:04:44.080606Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailStackSizeLargerThan1024.json"
2023-01-23T12:04:44.080611Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:04:44.080613Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-23T12:04:44.701868Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 26184658,
    events_root: None,
}
2023-01-23T12:04:44.701896Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T12:04:44.701903Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailStackSizeLargerThan1024"::Berlin::0
2023-01-23T12:04:44.701906Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailStackSizeLargerThan1024.json"
2023-01-23T12:04:44.701911Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:04:44.701913Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:04:44.702013Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-23T12:04:44.702020Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T12:04:44.702022Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailStackSizeLargerThan1024"::London::0
2023-01-23T12:04:44.702024Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailStackSizeLargerThan1024.json"
2023-01-23T12:04:44.702027Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:04:44.702028Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:04:44.702096Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-23T12:04:44.702102Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T12:04:44.702104Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFailStackSizeLargerThan1024"::Merge::0
2023-01-23T12:04:44.702107Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailStackSizeLargerThan1024.json"
2023-01-23T12:04:44.702111Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:04:44.702112Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:04:44.702179Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-23T12:04:44.703817Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFailStackSizeLargerThan1024.json"
2023-01-23T12:04:44.703969Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:621.968324ms

```
