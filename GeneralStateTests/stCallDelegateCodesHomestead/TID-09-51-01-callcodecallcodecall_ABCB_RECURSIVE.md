> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| KO | under native RT context |

* KO :: [FEVM | Eth Compliance Test | Hit with stack overflow error · Issue #1437 · filecoin-project/ref-fvm](https://github.com/filecoin-project/ref-fvm/issues/1437)

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_ABCB_RECURSIVE.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_ABCB_RECURSIVE.json \
	cargo run \
	-- \
	statetest
```

> For Review

- Execution looks OK (no stack overflow), use-case is cross-contract call between 3 contracts & there is recursive control flow using `DELEGATECALL`, & `CALL`, better to have opcode review & fevm execution control flow trace & muted state changed values.

- transaction::data is empty

```
"transaction" : {
	"data" : [
		"0x"
	],
	"gasLimit" : [
		"0x01c9c380"
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

> Opcodes

@0x1000000000000000000000000000000000000000

```
0000 PUSH1 0x40
0002 PUSH1 0x00
0004 PUSH1 0x40
0006 PUSH1 0x00
0008 PUSH20 0x1000000000000000000000000000000000000001
001d PUSH4 0x017d7840
0022 DELEGATECALL
0023 PUSH1 0x00
0025 SSTORE
0026 STOP
```

@0x1000000000000000000000000000000000000001

```
0000 PUSH1 0x40
0002 PUSH1 0x00
0004 PUSH1 0x40
0006 PUSH1 0x00
0008 PUSH20 0x1000000000000000000000000000000000000002
001d PUSH3 0x0f4240
0021 DELEGATECALL
0022 PUSH1 0x01
0024 SSTORE
0025 STOP
```

@0x1000000000000000000000000000000000000002

```
0000 PUSH1 0x40
0002 PUSH1 0x00
0004 PUSH1 0x40
0006 PUSH1 0x00
0008 PUSH1 0x00
000a PUSH20 0x1000000000000000000000000000000000000001
001f PUSH3 0x07a120
0023 CALL
0024 PUSH1 0x02
0026 SSTORE
0027 STOP
```



> Execution Trace

```
2023-01-22T06:30:19.625830Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_ABCB_RECURSIVE.json", Total Files :: 1
2023-01-22T06:30:19.626330Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_ABCB_RECURSIVE.json"
2023-01-22T06:30:19.739008Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-22T06:30:31.757723Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-22T06:30:31.757914Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T06:30:31.758000Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzacebnl4qs36lv6yeufvqp2v2ulyxw7fg4lsy74npykx6rbqt7tu7you
[DEBUG] fetching parameters block: 1
2023-01-22T06:30:31.761219Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-22T06:30:31.761365Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T06:30:31.761418Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([135, 86, 195, 226, 17, 192, 42, 192, 25, 213, 136, 254, 18, 95, 50, 68, 155, 121, 209, 130]) }
[DEBUG] getting cid: bafy2bzacec4vpktydmelpwnsx5wnk7ddcfjbcy4p32woetpf5pywtrugromus
[DEBUG] fetching parameters block: 1
2023-01-22T06:30:31.764686Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [202]
2023-01-22T06:30:31.764824Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T06:30:31.764872Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([121, 46, 44, 168, 100, 157, 195, 57, 208, 185, 119, 244, 82, 48, 8, 55, 203, 168, 19, 62]) }
[DEBUG] getting cid: bafy2bzaced2l3n2nphc2xwbukvf2fiooxrsdsoj7hd2rymybae7bd7owbz76m
[DEBUG] fetching parameters block: 1
2023-01-22T06:30:31.767759Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [203]
2023-01-22T06:30:31.767898Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T06:30:31.769086Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-22T06:30:31.769135Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_ABCB_RECURSIVE"::Istanbul::0
2023-01-22T06:30:31.769144Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_ABCB_RECURSIVE.json"
2023-01-22T06:30:31.769153Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T06:30:31.769159Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 1
2023-01-22T06:30:31.772316Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7107509,
    events_root: None,
}
2023-01-22T06:30:31.772368Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-22T06:30:31.772396Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_ABCB_RECURSIVE"::Berlin::0
2023-01-22T06:30:31.772404Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_ABCB_RECURSIVE.json"
2023-01-22T06:30:31.772411Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T06:30:31.772417Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 1
2023-01-22T06:30:31.775105Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6222695,
    events_root: None,
}
2023-01-22T06:30:31.775163Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-22T06:30:31.775199Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_ABCB_RECURSIVE"::London::0
2023-01-22T06:30:31.775206Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_ABCB_RECURSIVE.json"
2023-01-22T06:30:31.775214Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T06:30:31.775220Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 1
2023-01-22T06:30:31.778066Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6222695,
    events_root: None,
}
2023-01-22T06:30:31.778125Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-22T06:30:31.778164Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_ABCB_RECURSIVE"::Merge::0
2023-01-22T06:30:31.778172Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_ABCB_RECURSIVE.json"
2023-01-22T06:30:31.778180Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T06:30:31.778186Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 1
2023-01-22T06:30:31.780689Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6222695,
    events_root: None,
}
2023-01-22T06:30:31.782354Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_ABCB_RECURSIVE.json"
2023-01-22T06:30:31.782687Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:12.04175555s
```