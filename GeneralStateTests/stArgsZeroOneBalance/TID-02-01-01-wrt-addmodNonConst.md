> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| OK | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stArgsZeroOneBalance/addmodNonConst.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addmodNonConst.json \
	cargo run \
	-- \
	statetest
```

> Execution Trace

```
2023-01-20T11:18:58.525575Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addmodNonConst.json", Total Files :: 1
2023-01-20T11:18:58.526028Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addmodNonConst.json"
2023-01-20T11:18:58.638698Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [9, 94, 123, 174, 166, 166, 199, 196, 194, 223, 235, 151, 126, 250, 195, 38, 175, 85, 45, 135, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-20T11:19:11.204008Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-20T11:19:11.204254Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T11:19:11.204358Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzacecjf7f47u6czyqywnqsumzmvrtot2a55vtu22glmc44agihdvj5tu
[DEBUG] fetching parameters block: 1
2023-01-20T11:19:11.208023Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-20T11:19:11.208165Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T11:19:11.209346Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-20T11:19:11.209402Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmodNonConst"::Istanbul::0
2023-01-20T11:19:11.209417Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addmodNonConst.json"
2023-01-20T11:19:11.209426Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T11:19:11.209433Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:19:11.210327Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1694685,
    events_root: None,
}
2023-01-20T11:19:11.210358Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-20T11:19:11.210387Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmodNonConst"::Istanbul::0
2023-01-20T11:19:11.210394Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addmodNonConst.json"
2023-01-20T11:19:11.210401Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T11:19:11.210407Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:19:11.211029Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1694685,
    events_root: None,
}
2023-01-20T11:19:11.211059Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-20T11:19:11.211087Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmodNonConst"::Berlin::0
2023-01-20T11:19:11.211095Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addmodNonConst.json"
2023-01-20T11:19:11.211101Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T11:19:11.211107Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:19:11.211731Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1694685,
    events_root: None,
}
2023-01-20T11:19:11.211760Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-20T11:19:11.211788Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmodNonConst"::Berlin::0
2023-01-20T11:19:11.211795Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addmodNonConst.json"
2023-01-20T11:19:11.211802Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T11:19:11.211808Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:19:11.212437Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1694685,
    events_root: None,
}
2023-01-20T11:19:11.212467Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-20T11:19:11.212495Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmodNonConst"::London::0
2023-01-20T11:19:11.212502Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addmodNonConst.json"
2023-01-20T11:19:11.212509Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T11:19:11.212515Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:19:11.213154Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1694685,
    events_root: None,
}
2023-01-20T11:19:11.213183Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-20T11:19:11.213211Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmodNonConst"::London::0
2023-01-20T11:19:11.213218Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addmodNonConst.json"
2023-01-20T11:19:11.213225Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T11:19:11.213231Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:19:11.213910Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1694685,
    events_root: None,
}
2023-01-20T11:19:11.213940Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-20T11:19:11.213968Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmodNonConst"::Merge::0
2023-01-20T11:19:11.213975Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addmodNonConst.json"
2023-01-20T11:19:11.213982Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T11:19:11.213988Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:19:11.214609Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1694685,
    events_root: None,
}
2023-01-20T11:19:11.214638Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-20T11:19:11.214666Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmodNonConst"::Merge::0
2023-01-20T11:19:11.214673Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addmodNonConst.json"
2023-01-20T11:19:11.214680Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T11:19:11.214685Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T11:19:11.215307Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1694685,
    events_root: None,
}
2023-01-20T11:19:11.217362Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addmodNonConst.json"
2023-01-20T11:19:11.217706Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:12.576664218s
```
