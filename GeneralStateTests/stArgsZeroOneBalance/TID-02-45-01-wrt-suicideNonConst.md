> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| OK | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stArgsZeroOneBalance/suicideNonConst.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/suicideNonConst.json \
	cargo run \
	-- \
	statetest
```

> For Review

* `transaction::data` is empty | Execution Exit code is success

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
0016 SELFDESTRUCT
0017 STOP
```

> Execution Trace

```
2023-01-20T13:55:15.112460Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/suicideNonConst.json", Total Files :: 1
2023-01-20T13:55:15.112937Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/suicideNonConst.json"
2023-01-20T13:55:15.227602Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [9, 94, 123, 174, 166, 166, 199, 196, 194, 223, 235, 151, 126, 250, 195, 38, 175, 85, 45, 135, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-20T13:55:27.360549Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-20T13:55:27.360739Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T13:55:27.360817Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzacecjf7f47u6czyqywnqsumzmvrtot2a55vtu22glmc44agihdvj5tu
[DEBUG] fetching parameters block: 1
2023-01-20T13:55:27.363813Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-20T13:55:27.363952Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T13:55:27.365174Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-20T13:55:27.365232Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideNonConst"::Istanbul::0
2023-01-20T13:55:27.365248Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/suicideNonConst.json"
2023-01-20T13:55:27.365256Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T13:55:27.365263Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T13:55:27.367268Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3436180,
    events_root: None,
}
2023-01-20T13:55:27.367313Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-20T13:55:27.367364Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideNonConst"::Istanbul::0
2023-01-20T13:55:27.367372Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/suicideNonConst.json"
2023-01-20T13:55:27.367380Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T13:55:27.367386Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T13:55:27.367918Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1063706,
    events_root: None,
}
2023-01-20T13:55:27.367946Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-20T13:55:27.367975Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideNonConst"::Berlin::0
2023-01-20T13:55:27.367982Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/suicideNonConst.json"
2023-01-20T13:55:27.367989Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T13:55:27.367996Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T13:55:27.368444Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1063706,
    events_root: None,
}
2023-01-20T13:55:27.368469Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-20T13:55:27.368498Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideNonConst"::Berlin::0
2023-01-20T13:55:27.368505Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/suicideNonConst.json"
2023-01-20T13:55:27.368512Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T13:55:27.368518Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T13:55:27.368965Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1063706,
    events_root: None,
}
2023-01-20T13:55:27.368990Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-20T13:55:27.369020Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideNonConst"::London::0
2023-01-20T13:55:27.369027Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/suicideNonConst.json"
2023-01-20T13:55:27.369034Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T13:55:27.369040Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T13:55:27.369499Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1063706,
    events_root: None,
}
2023-01-20T13:55:27.369523Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-20T13:55:27.369552Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideNonConst"::London::0
2023-01-20T13:55:27.369559Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/suicideNonConst.json"
2023-01-20T13:55:27.369567Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T13:55:27.369572Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T13:55:27.370029Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1063706,
    events_root: None,
}
2023-01-20T13:55:27.370055Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-20T13:55:27.370084Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideNonConst"::Merge::0
2023-01-20T13:55:27.370091Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/suicideNonConst.json"
2023-01-20T13:55:27.370097Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T13:55:27.370104Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T13:55:27.370550Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1063706,
    events_root: None,
}
2023-01-20T13:55:27.370575Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-20T13:55:27.370603Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideNonConst"::Merge::0
2023-01-20T13:55:27.370611Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/suicideNonConst.json"
2023-01-20T13:55:27.370618Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T13:55:27.370624Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T13:55:27.371070Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1063706,
    events_root: None,
}
2023-01-20T13:55:27.373282Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/suicideNonConst.json"
2023-01-20T13:55:27.373603Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:12.143518943s
```
