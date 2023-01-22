> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| OK | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/EIPTests/stEIP3860/createInitCodeSizeLimit.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/EIPTests/stEIP3860/createInitCodeSizeLimit.json \
	cargo run \
	-- \
	statetest
```

> Execution Trace

```
2023-01-20T06:52:45.936465Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3860/createInitCodeSizeLimit.json", Total Files :: 1
2023-01-20T06:52:45.936914Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3860/createInitCodeSizeLimit.json"
2023-01-20T06:52:46.046306Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-20T06:52:58.463312Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-20T06:52:58.463529Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T06:52:58.463611Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [185, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzacecsquj7xh4vk2t3fxpfxek3wh4jdtmd7u5en66azvnwf7l4u47cl6
[DEBUG] fetching parameters block: 1
2023-01-20T06:52:58.466836Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-20T06:52:58.466979Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T06:52:58.467027Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [201, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([135, 86, 195, 226, 17, 192, 42, 192, 25, 213, 136, 254, 18, 95, 50, 68, 155, 121, 209, 130]) }
[DEBUG] getting cid: bafy2bzacec3meeo3jdxvlj7nv2juuin2lr32lkq4c6qs3zi2vijclcdc3pef2
[DEBUG] fetching parameters block: 1
2023-01-20T06:52:58.470290Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [202]
2023-01-20T06:52:58.470429Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T06:52:58.471616Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-20T06:52:58.471674Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitCodeSizeLimit"::Merge::0
2023-01-20T06:52:58.471684Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3860/createInitCodeSizeLimit.json"
2023-01-20T06:52:58.471692Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-20T06:52:58.471699Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [104, 35, 39, 18, 76, 93, 45, 192, 205, 33, 88, 186, 101, 211, 122, 195, 210, 20, 12, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
[DEBUG] getting cid: bafy2bzaceanrbgfir7n5i7xpwjhwbqcrsagne4hwifxykxci6eotucpcvfs2g
2023-01-20T06:52:58.475776Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12658625,
    events_root: None,
}
2023-01-20T06:52:58.475844Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-20T06:52:58.475894Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitCodeSizeLimit"::Merge::1
2023-01-20T06:52:58.475902Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3860/createInitCodeSizeLimit.json"
2023-01-20T06:52:58.475910Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-20T06:52:58.475916Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [104, 35, 39, 18, 76, 93, 45, 192, 205, 33, 88, 186, 101, 211, 122, 195, 210, 20, 12, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
[DEBUG] getting cid: bafy2bzaceanrbgfir7n5i7xpwjhwbqcrsagne4hwifxykxci6eotucpcvfs2g
2023-01-20T06:52:58.480023Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11762002,
    events_root: None,
}
2023-01-20T06:52:58.480104Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 0
2023-01-20T06:52:58.480158Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitCodeSizeLimit"::Shanghai::0
2023-01-20T06:52:58.480167Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3860/createInitCodeSizeLimit.json"
2023-01-20T06:52:58.480174Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-20T06:52:58.480181Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [104, 35, 39, 18, 76, 93, 45, 192, 205, 33, 88, 186, 101, 211, 122, 195, 210, 20, 12, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
[DEBUG] getting cid: bafy2bzaceanrbgfir7n5i7xpwjhwbqcrsagne4hwifxykxci6eotucpcvfs2g
2023-01-20T06:52:58.484097Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11762002,
    events_root: None,
}
2023-01-20T06:52:58.484171Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 1
2023-01-20T06:52:58.484228Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createInitCodeSizeLimit"::Shanghai::1
2023-01-20T06:52:58.484236Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3860/createInitCodeSizeLimit.json"
2023-01-20T06:52:58.484244Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-20T06:52:58.484251Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [104, 35, 39, 18, 76, 93, 45, 192, 205, 33, 88, 186, 101, 211, 122, 195, 210, 20, 12, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
[DEBUG] getting cid: bafy2bzaceanrbgfir7n5i7xpwjhwbqcrsagne4hwifxykxci6eotucpcvfs2g
2023-01-20T06:52:58.487736Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11762002,
    events_root: None,
}
2023-01-20T06:52:58.490322Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3860/createInitCodeSizeLimit.json"
2023-01-20T06:52:58.490675Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:12.44151928s
```