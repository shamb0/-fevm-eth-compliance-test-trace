> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| KO | under native RT context |

KO :: Implementation of delete_actor() is missing for test_vm runtime

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCallCodes/callcallcall_000_SuicideEnd.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000_SuicideEnd.json \
	cargo run \
	-- \
	statetest
```


> Execution Trace

```
2023-01-22T15:26:29.519674Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000_SuicideEnd.json", Total Files :: 1
2023-01-22T15:26:29.520093Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000_SuicideEnd.json"
2023-01-22T15:26:29.634174Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-22T15:26:41.533007Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-22T15:26:41.533201Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T15:26:41.533283Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzacebnl4qs36lv6yeufvqp2v2ulyxw7fg4lsy74npykx6rbqt7tu7you
[DEBUG] fetching parameters block: 1
2023-01-22T15:26:41.536717Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-22T15:26:41.536881Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T15:26:41.536945Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([135, 86, 195, 226, 17, 192, 42, 192, 25, 213, 136, 254, 18, 95, 50, 68, 155, 121, 209, 130]) }
[DEBUG] getting cid: bafy2bzacec4vpktydmelpwnsx5wnk7ddcfjbcy4p32woetpf5pywtrugromus
[DEBUG] fetching parameters block: 1
2023-01-22T15:26:41.540355Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [202]
2023-01-22T15:26:41.540494Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T15:26:41.540542Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([121, 46, 44, 168, 100, 157, 195, 57, 208, 185, 119, 244, 82, 48, 8, 55, 203, 168, 19, 62]) }
[DEBUG] getting cid: bafy2bzaced2l3n2nphc2xwbukvf2fiooxrsdsoj7hd2rymybae7bd7owbz76m
[DEBUG] fetching parameters block: 1
2023-01-22T15:26:41.543592Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [203]
2023-01-22T15:26:41.543731Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T15:26:41.543782Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([102, 145, 95, 210, 114, 99, 97, 196, 103, 113, 159, 135, 176, 147, 142, 56, 188, 98, 191, 170]) }
[DEBUG] getting cid: bafy2bzaceb2vfxtxbarnsm6smlwi5swqvpj7b2dgowoo5lruz7zqhi63wl77k
[DEBUG] fetching parameters block: 1
2023-01-22T15:26:41.546721Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [204]
2023-01-22T15:26:41.546878Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T15:26:41.548108Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-22T15:26:41.548152Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcall_000_SuicideEnd"::Istanbul::0
2023-01-22T15:26:41.548161Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000_SuicideEnd.json"
2023-01-22T15:26:41.548170Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T15:26:41.548177Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:26:41.549209Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1875954,
    events_root: None,
}
2023-01-22T15:26:41.549243Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-22T15:26:41.549266Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcall_000_SuicideEnd"::Berlin::0
2023-01-22T15:26:41.549273Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000_SuicideEnd.json"
2023-01-22T15:26:41.549280Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T15:26:41.549286Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:26:41.550040Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1875954,
    events_root: None,
}
2023-01-22T15:26:41.550070Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-22T15:26:41.550094Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcall_000_SuicideEnd"::London::0
2023-01-22T15:26:41.550101Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000_SuicideEnd.json"
2023-01-22T15:26:41.550108Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T15:26:41.550114Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:26:41.550860Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1875954,
    events_root: None,
}
2023-01-22T15:26:41.550891Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-22T15:26:41.550914Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcall_000_SuicideEnd"::Merge::0
2023-01-22T15:26:41.550921Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000_SuicideEnd.json"
2023-01-22T15:26:41.550928Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T15:26:41.550934Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:26:41.551676Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1875954,
    events_root: None,
}
2023-01-22T15:26:41.553491Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000_SuicideEnd.json"
2023-01-22T15:26:41.553825Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:11.917561663s
```