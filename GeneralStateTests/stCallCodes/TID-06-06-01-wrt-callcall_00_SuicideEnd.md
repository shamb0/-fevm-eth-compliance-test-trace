> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| KO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCallCodes/callcall_00_SuicideEnd.json#L15

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCallCodes/callcall_00_SuicideEnd.json \
	cargo run \
	-- \
	statetest
```

> For Review

`transaction.data` is empty & `CALL` opcode execution looks OK. `call` control switch to `0x1000000000000000000000000000000000000001` destination address & return value needs to be verified.

```
"transaction" : {
	"data" : [
		"0x"
	],
	"gasLimit" : [
		"0x2dc6c0"
	],
	"gasPrice" : "0x0a",
	"nonce" : "0x00",
	"secretKey" : "0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8",
	"sender" : "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
	"to" : "0x1000000000000000000000000000000000000000",
	"value" : [
		"0x00"
	]
}
```

> Opcode

```
0000 PUSH1 0x40
0002 PUSH1 0x00
0004 PUSH1 0x40
0006 PUSH1 0x00
0008 PUSH1 0x00
000a PUSH20 0x1000000000000000000000000000000000000001
001f PUSH3 0x0249f0
0023 CALL
0024 PUSH1 0x00
0026 SSTORE
0027 STOP
```

> Execution Trace

```
2023-01-21T10:24:16.353950Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stCallCodes/callcall_00_SuicideEnd.json", Total Files :: 1
2023-01-21T10:24:16.354395Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stCallCodes/callcall_00_SuicideEnd.json"
2023-01-21T10:24:16.469571Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-21T10:24:29.125531Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-21T10:24:29.125721Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-21T10:24:29.125798Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzacebnl4qs36lv6yeufvqp2v2ulyxw7fg4lsy74npykx6rbqt7tu7you
[DEBUG] fetching parameters block: 1
2023-01-21T10:24:29.128830Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-21T10:24:29.128965Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-21T10:24:29.129010Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([135, 86, 195, 226, 17, 192, 42, 192, 25, 213, 136, 254, 18, 95, 50, 68, 155, 121, 209, 130]) }
[DEBUG] getting cid: bafy2bzacec4vpktydmelpwnsx5wnk7ddcfjbcy4p32woetpf5pywtrugromus
[DEBUG] fetching parameters block: 1
2023-01-21T10:24:29.132133Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [202]
2023-01-21T10:24:29.132269Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-21T10:24:29.132313Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([121, 46, 44, 168, 100, 157, 195, 57, 208, 185, 119, 244, 82, 48, 8, 55, 203, 168, 19, 62]) }
[DEBUG] getting cid: bafy2bzaced2l3n2nphc2xwbukvf2fiooxrsdsoj7hd2rymybae7bd7owbz76m
[DEBUG] fetching parameters block: 1
2023-01-21T10:24:29.135109Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [203]
2023-01-21T10:24:29.135244Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-21T10:24:29.136394Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-21T10:24:29.136455Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcall_00_SuicideEnd"::Istanbul::0
2023-01-21T10:24:29.136468Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCodes/callcall_00_SuicideEnd.json"
2023-01-21T10:24:29.136479Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-21T10:24:29.136488Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-21T10:24:29.137562Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1875954,
    events_root: None,
}
2023-01-21T10:24:29.137596Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-21T10:24:29.137625Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcall_00_SuicideEnd"::Berlin::0
2023-01-21T10:24:29.137632Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCodes/callcall_00_SuicideEnd.json"
2023-01-21T10:24:29.137639Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-21T10:24:29.137645Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-21T10:24:29.138365Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1875954,
    events_root: None,
}
2023-01-21T10:24:29.138394Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-21T10:24:29.138422Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcall_00_SuicideEnd"::London::0
2023-01-21T10:24:29.138429Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCodes/callcall_00_SuicideEnd.json"
2023-01-21T10:24:29.138436Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-21T10:24:29.138442Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-21T10:24:29.139177Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1875954,
    events_root: None,
}
2023-01-21T10:24:29.139207Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-21T10:24:29.139235Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcall_00_SuicideEnd"::Merge::0
2023-01-21T10:24:29.139242Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCodes/callcall_00_SuicideEnd.json"
2023-01-21T10:24:29.139249Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-21T10:24:29.139254Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-21T10:24:29.139978Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1875954,
    events_root: None,
}
2023-01-21T10:24:29.142099Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stCallCodes/callcall_00_SuicideEnd.json"
2023-01-21T10:24:29.142449Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:12.670462041s
```