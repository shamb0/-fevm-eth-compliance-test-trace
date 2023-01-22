> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| OK | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stArgsZeroOneBalance/byteNonConst.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/byteNonConst.json \
	cargo run \
	-- \
	statetest
```

> For Review

* `transaction::data` is empty | Execution Success

```
"transaction" : {
	"data" : [
		"0x"
	],
	"gasLimit" : [
		"0x061a80"
	],
	"gasPrice" : "0x0a",
	"nonce" : "0x00",
	"secretKey" : "0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8",
	"sender" : "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
	"to" : "0x095e7baea6a6c7c4c2dfeb977efac326af552d87",
	"value" : [
		"0x00",
		"0x01"
	]
}
```

> opcodes

```
0000 PUSH20 0x095e7baea6a6c7c4c2dfeb977efac326af552d87
0015 BALANCE
0016 PUSH20 0x095e7baea6a6c7c4c2dfeb977efac326af552d87
002b BALANCE
002c BYTE
002d PUSH1 0x00
002f SSTORE
0030 STOP
```

> Execution Trace

```
2023-01-20T14:21:16.297135Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/byteNonConst.json", Total Files :: 1
2023-01-20T14:21:16.297784Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/byteNonConst.json"
2023-01-20T14:21:16.407218Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [9, 94, 123, 174, 166, 166, 199, 196, 194, 223, 235, 151, 126, 250, 195, 38, 175, 85, 45, 135, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-20T14:21:28.484938Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-20T14:21:28.485135Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T14:21:28.485214Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzacecjf7f47u6czyqywnqsumzmvrtot2a55vtu22glmc44agihdvj5tu
[DEBUG] fetching parameters block: 1
2023-01-20T14:21:28.488281Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-20T14:21:28.488423Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T14:21:28.489609Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-20T14:21:28.489666Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byteNonConst"::Istanbul::0
2023-01-20T14:21:28.489675Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/byteNonConst.json"
2023-01-20T14:21:28.489683Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T14:21:28.489690Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T14:21:28.490579Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1648902,
    events_root: None,
}
2023-01-20T14:21:28.490612Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-20T14:21:28.490641Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byteNonConst"::Istanbul::0
2023-01-20T14:21:28.490648Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/byteNonConst.json"
2023-01-20T14:21:28.490655Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T14:21:28.490661Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T14:21:28.491287Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1648902,
    events_root: None,
}
2023-01-20T14:21:28.491318Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-20T14:21:28.491347Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byteNonConst"::Berlin::0
2023-01-20T14:21:28.491354Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/byteNonConst.json"
2023-01-20T14:21:28.491361Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T14:21:28.491367Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T14:21:28.492001Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1648902,
    events_root: None,
}
2023-01-20T14:21:28.492030Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-20T14:21:28.492059Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byteNonConst"::Berlin::0
2023-01-20T14:21:28.492065Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/byteNonConst.json"
2023-01-20T14:21:28.492073Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T14:21:28.492079Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T14:21:28.492693Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1648902,
    events_root: None,
}
2023-01-20T14:21:28.492723Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-20T14:21:28.492752Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byteNonConst"::London::0
2023-01-20T14:21:28.492760Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/byteNonConst.json"
2023-01-20T14:21:28.492767Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T14:21:28.492773Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T14:21:28.493393Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1648902,
    events_root: None,
}
2023-01-20T14:21:28.493422Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-20T14:21:28.493450Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byteNonConst"::London::0
2023-01-20T14:21:28.493457Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/byteNonConst.json"
2023-01-20T14:21:28.493464Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T14:21:28.493470Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T14:21:28.494087Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1648902,
    events_root: None,
}
2023-01-20T14:21:28.494117Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-20T14:21:28.494144Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byteNonConst"::Merge::0
2023-01-20T14:21:28.494152Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/byteNonConst.json"
2023-01-20T14:21:28.494159Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T14:21:28.494166Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T14:21:28.494793Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1648902,
    events_root: None,
}
2023-01-20T14:21:28.494821Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-20T14:21:28.494850Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byteNonConst"::Merge::0
2023-01-20T14:21:28.494857Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/byteNonConst.json"
2023-01-20T14:21:28.494864Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T14:21:28.494870Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T14:21:28.495489Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1648902,
    events_root: None,
}
2023-01-20T14:21:28.497482Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/byteNonConst.json"
2023-01-20T14:21:28.497799Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:12.088324814s
```
