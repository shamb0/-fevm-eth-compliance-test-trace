> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| OK | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCallCreateCallCodeTest/createInitFail_OOGduringInit.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFail_OOGduringInit.json \
	cargo run --release \
	-- \
	statetest
```

> Execution Trace


```
2023-01-23T12:17:25.570866Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFail_OOGduringInit.json", Total Files :: 1
2023-01-23T12:17:25.571115Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFail_OOGduringInit.json"
2023-01-23T12:17:25.600091Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T12:17:25.600297Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T12:17:25.600301Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T12:17:25.600357Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T12:17:25.600431Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T12:17:25.600434Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFail_OOGduringInit"::Istanbul::0
2023-01-23T12:17:25.600437Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFail_OOGduringInit.json"
2023-01-23T12:17:25.600440Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:17:25.600442Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-23T12:17:26.219826Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14463152,
    events_root: None,
}
2023-01-23T12:17:26.219860Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T12:17:26.219867Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFail_OOGduringInit"::Berlin::0
2023-01-23T12:17:26.219870Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFail_OOGduringInit.json"
2023-01-23T12:17:26.219873Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:17:26.219875Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:17:26.219991Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-23T12:17:26.219998Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T12:17:26.220001Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFail_OOGduringInit"::London::0
2023-01-23T12:17:26.220003Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFail_OOGduringInit.json"
2023-01-23T12:17:26.220006Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:17:26.220008Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:17:26.220084Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-23T12:17:26.220091Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T12:17:26.220093Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitFail_OOGduringInit"::Merge::0
2023-01-23T12:17:26.220096Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFail_OOGduringInit.json"
2023-01-23T12:17:26.220099Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:17:26.220100Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:17:26.220172Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-23T12:17:26.221817Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitFail_OOGduringInit.json"
2023-01-23T12:17:26.221945Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:620.090328ms
```