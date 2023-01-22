> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| OK | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stArgsZeroOneBalance/balanceNonConst.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/balanceNonConst.json \
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
0016 BALANCE
0017 PUSH1 0x00
0019 SSTORE
001a STOP
```

> Execution Trace

```
2023-01-20T14:16:58.600738Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/balanceNonConst.json", Total Files :: 1
2023-01-20T14:16:58.601170Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/balanceNonConst.json"
2023-01-20T14:16:58.718710Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [9, 94, 123, 174, 166, 166, 199, 196, 194, 223, 235, 151, 126, 250, 195, 38, 175, 85, 45, 135, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-20T14:17:11.137440Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-20T14:17:11.137642Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T14:17:11.137729Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzacecjf7f47u6czyqywnqsumzmvrtot2a55vtu22glmc44agihdvj5tu
[DEBUG] fetching parameters block: 1
2023-01-20T14:17:11.140797Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-20T14:17:11.140941Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T14:17:11.142136Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-20T14:17:11.142193Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "balanceNonConst"::Istanbul::0
2023-01-20T14:17:11.142204Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/balanceNonConst.json"
2023-01-20T14:17:11.142214Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T14:17:11.142223Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T14:17:11.143343Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1630413,
    events_root: None,
}
2023-01-20T14:17:11.143379Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-20T14:17:11.143411Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "balanceNonConst"::Istanbul::0
2023-01-20T14:17:11.143418Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/balanceNonConst.json"
2023-01-20T14:17:11.143427Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T14:17:11.143436Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T14:17:11.144280Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1630413,
    events_root: None,
}
2023-01-20T14:17:11.144313Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-20T14:17:11.144343Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "balanceNonConst"::Berlin::0
2023-01-20T14:17:11.144351Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/balanceNonConst.json"
2023-01-20T14:17:11.144360Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T14:17:11.144369Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T14:17:11.145233Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1630413,
    events_root: None,
}
2023-01-20T14:17:11.145265Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-20T14:17:11.145296Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "balanceNonConst"::Berlin::0
2023-01-20T14:17:11.145310Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/balanceNonConst.json"
2023-01-20T14:17:11.145319Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T14:17:11.145327Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T14:17:11.146174Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1630413,
    events_root: None,
}
2023-01-20T14:17:11.146207Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-20T14:17:11.146237Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "balanceNonConst"::London::0
2023-01-20T14:17:11.146245Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/balanceNonConst.json"
2023-01-20T14:17:11.146255Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T14:17:11.146263Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T14:17:11.147112Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1630413,
    events_root: None,
}
2023-01-20T14:17:11.147143Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-20T14:17:11.147174Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "balanceNonConst"::London::0
2023-01-20T14:17:11.147182Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/balanceNonConst.json"
2023-01-20T14:17:11.147191Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T14:17:11.147200Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T14:17:11.148068Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1630413,
    events_root: None,
}
2023-01-20T14:17:11.148100Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-20T14:17:11.148130Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "balanceNonConst"::Merge::0
2023-01-20T14:17:11.148138Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/balanceNonConst.json"
2023-01-20T14:17:11.148147Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T14:17:11.148156Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T14:17:11.149121Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1630413,
    events_root: None,
}
2023-01-20T14:17:11.149158Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-20T14:17:11.149198Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "balanceNonConst"::Merge::0
2023-01-20T14:17:11.149208Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/balanceNonConst.json"
2023-01-20T14:17:11.149217Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T14:17:11.149226Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T14:17:11.150331Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1630413,
    events_root: None,
}
2023-01-20T14:17:11.152783Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/balanceNonConst.json"
2023-01-20T14:17:11.153055Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:12.431678969s
```
