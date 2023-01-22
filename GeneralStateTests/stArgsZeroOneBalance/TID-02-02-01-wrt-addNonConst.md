
> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| OK | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stArgsZeroOneBalance/addNonConst.json#L8

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addNonConst.json \
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

> Opcode

```
0000 PUSH20 0x095e7baea6a6c7c4c2dfeb977efac326af552d87
0015 BALANCE
0016 PUSH20 0x095e7baea6a6c7c4c2dfeb977efac326af552d87
002b BALANCE
002c ADD
002d PUSH1 0x00
002f SSTORE
0030 STOP
```

> Execution Trace

```
2023-01-20T14:06:08.997326Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addNonConst.json", Total Files :: 1
2023-01-20T14:06:08.997718Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addNonConst.json"
2023-01-20T14:06:09.111277Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [9, 94, 123, 174, 166, 166, 199, 196, 194, 223, 235, 151, 126, 250, 195, 38, 175, 85, 45, 135, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-20T14:06:20.909585Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-20T14:06:20.909771Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T14:06:20.909848Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzacecjf7f47u6czyqywnqsumzmvrtot2a55vtu22glmc44agihdvj5tu
[DEBUG] fetching parameters block: 1
2023-01-20T14:06:20.912693Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-20T14:06:20.912827Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T14:06:20.913964Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-20T14:06:20.914019Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addNonConst"::Istanbul::0
2023-01-20T14:06:20.914028Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addNonConst.json"
2023-01-20T14:06:20.914036Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T14:06:20.914043Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T14:06:20.914865Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1648734,
    events_root: None,
}
2023-01-20T14:06:20.914896Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-20T14:06:20.914923Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addNonConst"::Istanbul::0
2023-01-20T14:06:20.914930Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addNonConst.json"
2023-01-20T14:06:20.914936Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T14:06:20.914942Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T14:06:20.915524Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1648734,
    events_root: None,
}
2023-01-20T14:06:20.915552Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-20T14:06:20.915579Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addNonConst"::Berlin::0
2023-01-20T14:06:20.915586Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addNonConst.json"
2023-01-20T14:06:20.915593Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T14:06:20.915599Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T14:06:20.916179Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1648734,
    events_root: None,
}
2023-01-20T14:06:20.916206Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-20T14:06:20.916234Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addNonConst"::Berlin::0
2023-01-20T14:06:20.916240Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addNonConst.json"
2023-01-20T14:06:20.916247Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T14:06:20.916253Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T14:06:20.916833Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1648734,
    events_root: None,
}
2023-01-20T14:06:20.916861Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-20T14:06:20.916888Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addNonConst"::London::0
2023-01-20T14:06:20.916895Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addNonConst.json"
2023-01-20T14:06:20.916902Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T14:06:20.916908Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T14:06:20.917498Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1648734,
    events_root: None,
}
2023-01-20T14:06:20.917526Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-20T14:06:20.917554Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addNonConst"::London::0
2023-01-20T14:06:20.917560Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addNonConst.json"
2023-01-20T14:06:20.917567Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T14:06:20.917573Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T14:06:20.918159Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1648734,
    events_root: None,
}
2023-01-20T14:06:20.918187Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-20T14:06:20.918214Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addNonConst"::Merge::0
2023-01-20T14:06:20.918221Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addNonConst.json"
2023-01-20T14:06:20.918228Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T14:06:20.918234Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T14:06:20.918815Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1648734,
    events_root: None,
}
2023-01-20T14:06:20.918842Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-20T14:06:20.918869Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addNonConst"::Merge::0
2023-01-20T14:06:20.918876Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addNonConst.json"
2023-01-20T14:06:20.918882Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T14:06:20.918889Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T14:06:20.919469Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1648734,
    events_root: None,
}
2023-01-20T14:06:20.921612Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addNonConst.json"
2023-01-20T14:06:20.921934Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:11.808244514s
```
