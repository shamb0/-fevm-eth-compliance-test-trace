> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| OK | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCallCreateCallCodeTest/createInitOOGforCREATE.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitOOGforCREATE.json \
	cargo run --release \
	-- \
	statetest
```

> Execution Trace

```
2023-01-23T12:20:31.419382Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitOOGforCREATE.json", Total Files :: 1
2023-01-23T12:20:31.419629Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitOOGforCREATE.json"
2023-01-23T12:20:31.448085Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T12:20:31.448288Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T12:20:31.448292Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T12:20:31.448346Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T12:20:31.448420Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T12:20:31.448424Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitOOGforCREATE"::Istanbul::0
2023-01-23T12:20:31.448426Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitOOGforCREATE.json"
2023-01-23T12:20:31.448430Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:20:31.448431Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-23T12:20:32.113584Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14463152,
    events_root: None,
}
2023-01-23T12:20:32.113613Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T12:20:32.113621Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitOOGforCREATE"::Istanbul::0
2023-01-23T12:20:32.113624Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitOOGforCREATE.json"
2023-01-23T12:20:32.113627Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:20:32.113630Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:20:32.113726Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-23T12:20:32.113732Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T12:20:32.113735Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitOOGforCREATE"::Berlin::0
2023-01-23T12:20:32.113737Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitOOGforCREATE.json"
2023-01-23T12:20:32.113739Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:20:32.113741Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:20:32.113804Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-23T12:20:32.113810Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T12:20:32.113813Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitOOGforCREATE"::Berlin::0
2023-01-23T12:20:32.113815Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitOOGforCREATE.json"
2023-01-23T12:20:32.113817Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:20:32.113819Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:20:32.113880Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-23T12:20:32.113885Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T12:20:32.113888Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitOOGforCREATE"::London::0
2023-01-23T12:20:32.113890Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitOOGforCREATE.json"
2023-01-23T12:20:32.113892Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:20:32.113894Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:20:32.113956Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-23T12:20:32.113963Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T12:20:32.113965Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitOOGforCREATE"::London::0
2023-01-23T12:20:32.113967Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitOOGforCREATE.json"
2023-01-23T12:20:32.113970Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:20:32.113971Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:20:32.114034Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-23T12:20:32.114039Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T12:20:32.114041Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitOOGforCREATE"::Merge::0
2023-01-23T12:20:32.114043Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitOOGforCREATE.json"
2023-01-23T12:20:32.114046Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:20:32.114047Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:20:32.114108Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-23T12:20:32.114113Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T12:20:32.114116Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitOOGforCREATE"::Merge::0
2023-01-23T12:20:32.114118Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitOOGforCREATE.json"
2023-01-23T12:20:32.114120Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T12:20:32.114122Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T12:20:32.114182Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-23T12:20:32.115761Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createInitOOGforCREATE.json"
2023-01-23T12:20:32.115897Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:666.105878ms
```