> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| KO | under native RT context |

KO :: Implementation of delete_actor() is missing for test_vm runtime

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCallCodes/callcallcallcode_001_SuicideEnd.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_SuicideEnd.json \
	cargo run --release \
	-- \
	statetest
```

> Execution Trace

```
2023-01-22T15:34:58.686562Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_SuicideEnd.json", Total Files :: 1
2023-01-22T15:34:58.687021Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_SuicideEnd.json"
2023-01-22T15:34:58.798037Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-22T15:35:11.112486Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-22T15:35:11.112674Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T15:35:11.112751Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzacebnl4qs36lv6yeufvqp2v2ulyxw7fg4lsy74npykx6rbqt7tu7you
[DEBUG] fetching parameters block: 1
2023-01-22T15:35:11.115863Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-22T15:35:11.116008Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T15:35:11.116057Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([135, 86, 195, 226, 17, 192, 42, 192, 25, 213, 136, 254, 18, 95, 50, 68, 155, 121, 209, 130]) }
[DEBUG] getting cid: bafy2bzacec4vpktydmelpwnsx5wnk7ddcfjbcy4p32woetpf5pywtrugromus
[DEBUG] fetching parameters block: 1
2023-01-22T15:35:11.119264Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [202]
2023-01-22T15:35:11.119401Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T15:35:11.119448Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([121, 46, 44, 168, 100, 157, 195, 57, 208, 185, 119, 244, 82, 48, 8, 55, 203, 168, 19, 62]) }
[DEBUG] getting cid: bafy2bzaced2l3n2nphc2xwbukvf2fiooxrsdsoj7hd2rymybae7bd7owbz76m
[DEBUG] fetching parameters block: 1
2023-01-22T15:35:11.122464Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [203]
2023-01-22T15:35:11.122602Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T15:35:11.122652Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([102, 145, 95, 210, 114, 99, 97, 196, 103, 113, 159, 135, 176, 147, 142, 56, 188, 98, 191, 170]) }
[DEBUG] getting cid: bafy2bzaceb2vfxtxbarnsm6smlwi5swqvpj7b2dgowoo5lruz7zqhi63wl77k
[DEBUG] fetching parameters block: 1
2023-01-22T15:35:11.125547Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [204]
2023-01-22T15:35:11.125684Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T15:35:11.126860Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-22T15:35:11.126900Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_SuicideEnd"::Istanbul::0
2023-01-22T15:35:11.126910Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_SuicideEnd.json"
2023-01-22T15:35:11.126918Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T15:35:11.126925Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:35:11.127913Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1875954,
    events_root: None,
}
2023-01-22T15:35:11.127947Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-22T15:35:11.127970Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_SuicideEnd"::Berlin::0
2023-01-22T15:35:11.127977Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_SuicideEnd.json"
2023-01-22T15:35:11.127985Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T15:35:11.127990Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:35:11.128728Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1875954,
    events_root: None,
}
2023-01-22T15:35:11.128758Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-22T15:35:11.128781Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_SuicideEnd"::London::0
2023-01-22T15:35:11.128789Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_SuicideEnd.json"
2023-01-22T15:35:11.128796Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T15:35:11.128802Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:35:11.129558Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1875954,
    events_root: None,
}
2023-01-22T15:35:11.129588Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-22T15:35:11.129610Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_SuicideEnd"::Merge::0
2023-01-22T15:35:11.129618Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_SuicideEnd.json"
2023-01-22T15:35:11.129625Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T15:35:11.129631Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:35:11.130371Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1875954,
    events_root: None,
}
2023-01-22T15:35:11.132730Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_SuicideEnd.json"
2023-01-22T15:35:11.133074Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:12.332391342s
```