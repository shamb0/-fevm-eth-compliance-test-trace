> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| OK | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCallCodes/callcallcallcode_001_SuicideMiddle.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_SuicideMiddle.json \
	cargo run --release \
	-- \
	statetest
```

> Execution Trace

```
2023-01-23T11:21:22.484583Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_SuicideMiddle.json", Total Files :: 1
2023-01-23T11:21:22.484845Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_SuicideMiddle.json"
2023-01-23T11:21:22.512795Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T11:21:22.513019Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T11:21:22.513024Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T11:21:22.513076Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T11:21:22.513078Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-23T11:21:22.513136Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T11:21:22.513138Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-23T11:21:22.513193Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T11:21:22.513195Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-23T11:21:22.513246Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T11:21:22.513319Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T11:21:22.513322Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_SuicideMiddle"::Istanbul::0
2023-01-23T11:21:22.513325Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_SuicideMiddle.json"
2023-01-23T11:21:22.513329Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T11:21:22.513331Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T11:21:22.847970Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-23T11:21:22.848004Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T11:21:22.848015Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_SuicideMiddle"::Berlin::0
2023-01-23T11:21:22.848018Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_SuicideMiddle.json"
2023-01-23T11:21:22.848022Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T11:21:22.848023Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T11:21:22.848145Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-23T11:21:22.848154Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T11:21:22.848157Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_SuicideMiddle"::London::0
2023-01-23T11:21:22.848159Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_SuicideMiddle.json"
2023-01-23T11:21:22.848161Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T11:21:22.848163Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T11:21:22.848268Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-23T11:21:22.848275Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T11:21:22.848278Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_SuicideMiddle"::Merge::0
2023-01-23T11:21:22.848280Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_SuicideMiddle.json"
2023-01-23T11:21:22.848283Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T11:21:22.848284Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T11:21:22.848411Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-23T11:21:22.850269Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_SuicideMiddle.json"
2023-01-23T11:21:22.850462Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:335.630185ms
```