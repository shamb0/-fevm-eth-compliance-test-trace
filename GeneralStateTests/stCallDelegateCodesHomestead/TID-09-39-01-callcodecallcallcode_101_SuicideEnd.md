> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| KO | under native RT context |

* KO :: [FEVM | Eth Compliance Test | Hit with stack overflow error · Issue #1437 · filecoin-project/ref-fvm](https://github.com/filecoin-project/ref-fvm/issues/1437)


> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101_SuicideEnd.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101_SuicideEnd.json \
	cargo run \
	-- \
	statetest
```

> For Review

> For Review

- Execution looks OK (no stack overflow), use-case is cross-contract call between 4 contracts & there is recursive control flow using `CALL` & has `SELFDESTRUCT`, better to have opcode review & fevm execution control flow trace & muted state changed values.

- transaction::data is empty

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

> Opcodes

@0x1000000000000000000000000000000000000000

```
0000 PUSH1 0x40
0002 PUSH1 0x00
0004 PUSH1 0x40
0006 PUSH1 0x00
0008 PUSH20 0x1000000000000000000000000000000000000001
001d PUSH3 0x0249f0
0021 DELEGATECALL
0022 PUSH1 0x00
0024 SSTORE
0025 STOP
```

@0x1000000000000000000000000000000000000001

```
0000 PUSH1 0x40
0002 PUSH1 0x00
0004 PUSH1 0x40
0006 PUSH1 0x00
0008 PUSH1 0x00
000a PUSH20 0x1000000000000000000000000000000000000002
001f PUSH3 0x0186a0
0023 CALL
0024 PUSH1 0x01
0026 SSTORE
0027 STOP
```

@0x1000000000000000000000000000000000000002

```
0000 PUSH1 0x40
0002 PUSH1 0x00
0004 PUSH1 0x40
0006 PUSH1 0x00
0008 PUSH20 0x1000000000000000000000000000000000000003
001d PUSH2 0xc350
0020 DELEGATECALL
0021 PUSH1 0x02
0023 SSTORE
0024 PUSH20 0x1000000000000000000000000000000000000001
0039 SELFDESTRUCT
003a STOP
```

@0x1000000000000000000000000000000000000003

```
0000 PUSH1 0x01
0002 PUSH1 0x03
0004 SSTORE
0005 STOP
```

> Execution Trace

```
2023-01-22T06:09:17.094280Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101_SuicideEnd.json", Total Files :: 1
2023-01-22T06:09:17.094711Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101_SuicideEnd.json"
2023-01-22T06:09:17.210304Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-22T06:09:29.309263Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-22T06:09:29.309464Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T06:09:29.309552Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzacebnl4qs36lv6yeufvqp2v2ulyxw7fg4lsy74npykx6rbqt7tu7you
[DEBUG] fetching parameters block: 1
2023-01-22T06:09:29.312909Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-22T06:09:29.313080Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T06:09:29.313148Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([135, 86, 195, 226, 17, 192, 42, 192, 25, 213, 136, 254, 18, 95, 50, 68, 155, 121, 209, 130]) }
[DEBUG] getting cid: bafy2bzacec4vpktydmelpwnsx5wnk7ddcfjbcy4p32woetpf5pywtrugromus
[DEBUG] fetching parameters block: 1
2023-01-22T06:09:29.316537Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [202]
2023-01-22T06:09:29.316679Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T06:09:29.316731Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([121, 46, 44, 168, 100, 157, 195, 57, 208, 185, 119, 244, 82, 48, 8, 55, 203, 168, 19, 62]) }
[DEBUG] getting cid: bafy2bzaced2l3n2nphc2xwbukvf2fiooxrsdsoj7hd2rymybae7bd7owbz76m
[DEBUG] fetching parameters block: 1
2023-01-22T06:09:29.319764Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [203]
2023-01-22T06:09:29.319910Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T06:09:29.319967Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([102, 145, 95, 210, 114, 99, 97, 196, 103, 113, 159, 135, 176, 147, 142, 56, 188, 98, 191, 170]) }
[DEBUG] getting cid: bafy2bzaceb2vfxtxbarnsm6smlwi5swqvpj7b2dgowoo5lruz7zqhi63wl77k
[DEBUG] fetching parameters block: 1
2023-01-22T06:09:29.323196Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [204]
2023-01-22T06:09:29.323353Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T06:09:29.324577Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-22T06:09:29.324629Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_SuicideEnd"::Istanbul::0
2023-01-22T06:09:29.324638Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101_SuicideEnd.json"
2023-01-22T06:09:29.324646Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T06:09:29.324653Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
2023-01-22T06:09:29.326400Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2813686,
    events_root: None,
}
2023-01-22T06:09:29.326459Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-22T06:09:29.326504Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_SuicideEnd"::Berlin::0
2023-01-22T06:09:29.326512Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101_SuicideEnd.json"
2023-01-22T06:09:29.326520Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T06:09:29.326526Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
2023-01-22T06:09:29.327801Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2813686,
    events_root: None,
}
2023-01-22T06:09:29.327841Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-22T06:09:29.327875Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_SuicideEnd"::London::0
2023-01-22T06:09:29.327882Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101_SuicideEnd.json"
2023-01-22T06:09:29.327889Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T06:09:29.327895Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
2023-01-22T06:09:29.329069Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2813686,
    events_root: None,
}
2023-01-22T06:09:29.329103Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-22T06:09:29.329131Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_SuicideEnd"::Merge::0
2023-01-22T06:09:29.329138Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101_SuicideEnd.json"
2023-01-22T06:09:29.329145Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T06:09:29.329151Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
2023-01-22T06:09:29.330321Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2813686,
    events_root: None,
}
2023-01-22T06:09:29.332477Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101_SuicideEnd.json"
2023-01-22T06:09:29.332824Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:12.120080858s
```