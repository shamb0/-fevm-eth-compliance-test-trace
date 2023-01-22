> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| OK | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/EIPTests/stEIP3860/create2InitCodeSizeLimit.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/EIPTests/stEIP3860/create2InitCodeSizeLimit.json \
	cargo run \
	-- \
	statetest
```

> Execution Trace

```
2023-01-20T06:49:43.699061Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3860/create2InitCodeSizeLimit.json", Total Files :: 1
2023-01-20T06:49:43.699504Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3860/create2InitCodeSizeLimit.json"
2023-01-20T06:49:43.813728Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-20T06:49:56.287502Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-20T06:49:56.287705Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T06:49:56.287783Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [185, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzacecsquj7xh4vk2t3fxpfxek3wh4jdtmd7u5en66azvnwf7l4u47cl6
[DEBUG] fetching parameters block: 1
2023-01-20T06:49:56.290990Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-20T06:49:56.291133Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T06:49:56.291184Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [201, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([135, 86, 195, 226, 17, 192, 42, 192, 25, 213, 136, 254, 18, 95, 50, 68, 155, 121, 209, 130]) }
[DEBUG] getting cid: bafy2bzacec3meeo3jdxvlj7nv2juuin2lr32lkq4c6qs3zi2vijclcdc3pef2
[DEBUG] fetching parameters block: 1
2023-01-20T06:49:56.294478Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [202]
2023-01-20T06:49:56.294619Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T06:49:56.295831Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-20T06:49:56.295891Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "create2InitCodeSizeLimit"::Merge::0
2023-01-20T06:49:56.295901Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3860/create2InitCodeSizeLimit.json"
2023-01-20T06:49:56.295910Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-20T06:49:56.295918Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T06:49:56.298493Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 8470170,
    events_root: None,
}
2023-01-20T06:49:56.298547Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-20T06:49:56.298588Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "create2InitCodeSizeLimit"::Merge::1
2023-01-20T06:49:56.298596Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3860/create2InitCodeSizeLimit.json"
2023-01-20T06:49:56.298603Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-20T06:49:56.298610Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T06:49:56.300683Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7358149,
    events_root: None,
}
2023-01-20T06:49:56.300730Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 0
2023-01-20T06:49:56.300762Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "create2InitCodeSizeLimit"::Shanghai::0
2023-01-20T06:49:56.300769Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3860/create2InitCodeSizeLimit.json"
2023-01-20T06:49:56.300777Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-20T06:49:56.300783Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T06:49:56.302791Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7357981,
    events_root: None,
}
2023-01-20T06:49:56.302836Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 1
2023-01-20T06:49:56.302866Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "create2InitCodeSizeLimit"::Shanghai::1
2023-01-20T06:49:56.302874Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3860/create2InitCodeSizeLimit.json"
2023-01-20T06:49:56.302881Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-20T06:49:56.302888Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T06:49:56.304898Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7358149,
    events_root: None,
}
2023-01-20T06:49:56.307072Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/EIPTests/stEIP3860/create2InitCodeSizeLimit.json"
2023-01-20T06:49:56.307335Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:12.491243051s
```