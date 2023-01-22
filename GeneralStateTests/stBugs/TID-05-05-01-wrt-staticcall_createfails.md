> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stBugs/staticcall_createfails.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stBugs/staticcall_createfails.json \
	cargo run \
	-- \
	statetest
```

> Execution Trace

```
2023-01-20T15:24:08.221138Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stBugs/staticcall_createfails.json", Total Files :: 1
2023-01-20T15:24:08.221681Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stBugs/staticcall_createfails.json"
2023-01-20T15:24:08.331085Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-20T15:24:20.284370Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-20T15:24:20.284555Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T15:24:20.284641Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [185, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzacecsquj7xh4vk2t3fxpfxek3wh4jdtmd7u5en66azvnwf7l4u47cl6
[DEBUG] fetching parameters block: 1
2023-01-20T15:24:20.287851Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-20T15:24:20.287996Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T15:24:20.288042Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [201, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([135, 86, 195, 226, 17, 192, 42, 192, 25, 213, 136, 254, 18, 95, 50, 68, 155, 121, 209, 130]) }
[DEBUG] getting cid: bafy2bzacec3meeo3jdxvlj7nv2juuin2lr32lkq4c6qs3zi2vijclcdc3pef2
[DEBUG] fetching parameters block: 1
2023-01-20T15:24:20.291352Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [202]
2023-01-20T15:24:20.291497Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T15:24:20.291544Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [217, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([121, 46, 44, 168, 100, 157, 195, 57, 208, 185, 119, 244, 82, 48, 8, 55, 203, 168, 19, 62]) }
[DEBUG] getting cid: bafy2bzaceajgvxqhinbqkp5iinprlfg25zfxyy2lrha7bjrb5kk4s6bepdqpy
[DEBUG] fetching parameters block: 1
2023-01-20T15:24:20.294611Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [203]
2023-01-20T15:24:20.294754Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T15:24:20.295996Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-20T15:24:20.296055Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "staticcall_createfails"::Istanbul::0
2023-01-20T15:24:20.296064Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBugs/staticcall_createfails.json"
2023-01-20T15:24:20.296072Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-20T15:24:20.296080Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T15:24:20.297121Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1759172,
    events_root: None,
}
2023-01-20T15:24:20.297154Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-20T15:24:20.297185Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "staticcall_createfails"::Istanbul::1
2023-01-20T15:24:20.297192Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBugs/staticcall_createfails.json"
2023-01-20T15:24:20.297199Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-20T15:24:20.297204Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T15:24:20.298155Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1759172,
    events_root: None,
}
2023-01-20T15:24:20.298184Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-20T15:24:20.298212Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "staticcall_createfails"::Berlin::0
2023-01-20T15:24:20.298221Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBugs/staticcall_createfails.json"
2023-01-20T15:24:20.298228Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-20T15:24:20.298234Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T15:24:20.298947Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1759172,
    events_root: None,
}
2023-01-20T15:24:20.298975Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-20T15:24:20.299012Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "staticcall_createfails"::Berlin::1
2023-01-20T15:24:20.299024Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBugs/staticcall_createfails.json"
2023-01-20T15:24:20.299034Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-20T15:24:20.299042Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T15:24:20.299910Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1759172,
    events_root: None,
}
2023-01-20T15:24:20.299950Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-20T15:24:20.299993Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "staticcall_createfails"::London::0
2023-01-20T15:24:20.300001Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBugs/staticcall_createfails.json"
2023-01-20T15:24:20.300008Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-20T15:24:20.300014Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T15:24:20.300826Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1759172,
    events_root: None,
}
2023-01-20T15:24:20.300858Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-20T15:24:20.300892Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "staticcall_createfails"::London::1
2023-01-20T15:24:20.300901Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBugs/staticcall_createfails.json"
2023-01-20T15:24:20.300908Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-20T15:24:20.300914Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T15:24:20.301765Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1759172,
    events_root: None,
}
2023-01-20T15:24:20.301796Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-20T15:24:20.301828Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "staticcall_createfails"::Merge::0
2023-01-20T15:24:20.301835Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBugs/staticcall_createfails.json"
2023-01-20T15:24:20.301842Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-20T15:24:20.301848Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T15:24:20.302587Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1759172,
    events_root: None,
}
2023-01-20T15:24:20.302624Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-20T15:24:20.302665Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "staticcall_createfails"::Merge::1
2023-01-20T15:24:20.302675Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBugs/staticcall_createfails.json"
2023-01-20T15:24:20.302685Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-20T15:24:20.302694Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T15:24:20.303436Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1759172,
    events_root: None,
}
2023-01-20T15:24:20.305956Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stBugs/staticcall_createfails.json"
2023-01-20T15:24:20.306235Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:11.972408183s
```
