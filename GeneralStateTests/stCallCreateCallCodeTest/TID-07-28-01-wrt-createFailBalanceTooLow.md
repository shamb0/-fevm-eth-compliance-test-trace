> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| OK | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCallCreateCallCodeTest/createFailBalanceTooLow.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createFailBalanceTooLow.json \
	cargo run --release \
	-- \
	statetest
```

> Execution Trace

```
2023-01-23T11:30:16.468393Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createFailBalanceTooLow.json", Total Files :: 1
2023-01-23T11:30:16.468644Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createFailBalanceTooLow.json"
2023-01-23T11:30:16.498457Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T11:30:16.498682Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T11:30:16.498686Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T11:30:16.498742Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T11:30:16.498816Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T11:30:16.498820Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createFailBalanceTooLow"::Istanbul::0
2023-01-23T11:30:16.498823Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createFailBalanceTooLow.json"
2023-01-23T11:30:16.498826Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T11:30:16.498828Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T11:30:16.839728Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3585372,
    events_root: None,
}
2023-01-23T11:30:16.839754Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T11:30:16.839762Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createFailBalanceTooLow"::Istanbul::0
2023-01-23T11:30:16.839765Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createFailBalanceTooLow.json"
2023-01-23T11:30:16.839768Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T11:30:16.839770Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T11:30:16.839861Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-23T11:30:16.839868Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T11:30:16.839870Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createFailBalanceTooLow"::Berlin::0
2023-01-23T11:30:16.839872Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createFailBalanceTooLow.json"
2023-01-23T11:30:16.839875Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T11:30:16.839876Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T11:30:16.839944Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-23T11:30:16.839949Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T11:30:16.839952Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createFailBalanceTooLow"::Berlin::0
2023-01-23T11:30:16.839953Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createFailBalanceTooLow.json"
2023-01-23T11:30:16.839956Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T11:30:16.839958Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T11:30:16.840033Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-23T11:30:16.840039Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T11:30:16.840042Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createFailBalanceTooLow"::London::0
2023-01-23T11:30:16.840043Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createFailBalanceTooLow.json"
2023-01-23T11:30:16.840046Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T11:30:16.840047Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T11:30:16.840112Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-23T11:30:16.840117Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T11:30:16.840120Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createFailBalanceTooLow"::London::0
2023-01-23T11:30:16.840122Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createFailBalanceTooLow.json"
2023-01-23T11:30:16.840124Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T11:30:16.840125Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T11:30:16.840191Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-23T11:30:16.840196Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T11:30:16.840199Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createFailBalanceTooLow"::Merge::0
2023-01-23T11:30:16.840200Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createFailBalanceTooLow.json"
2023-01-23T11:30:16.840203Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T11:30:16.840204Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T11:30:16.840268Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-23T11:30:16.840275Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T11:30:16.840278Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createFailBalanceTooLow"::Merge::0
2023-01-23T11:30:16.840279Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createFailBalanceTooLow.json"
2023-01-23T11:30:16.840282Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T11:30:16.840283Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T11:30:16.840347Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-23T11:30:16.842176Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/createFailBalanceTooLow.json"
2023-01-23T11:30:16.842325Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:341.900626ms
```