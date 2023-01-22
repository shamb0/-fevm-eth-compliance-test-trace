> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| KO | under native RT context |

* KO :: [FEVM | Eth Compliance Test | Hit with stack overflow error · Issue #1437 · filecoin-project/ref-fvm](https://github.com/filecoin-project/ref-fvm/issues/1437)


> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_ABCB_RECURSIVE.json#L1


> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_ABCB_RECURSIVE.json \
	cargo run \
	-- \
	statetest
```

> For Review

- Execution looks OK (no stack overflow), use-case is cross-contract call between 3 contracts & there is recursive control flow using `CALL` & `DELEGATECALL`, better to have opcode review & fevm execution control flow trace & muted state changed values.

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
0008 PUSH1 0x00
000a PUSH20 0x1000000000000000000000000000000000000001
001f PUSH4 0x017d7840
0024 CALL
0025 PUSH1 0x00
0027 SSTORE
0028 STOP
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
0008 PUSH20 0x1000000000000000000000000000000000000001
001d PUSH3 0x07a120
0021 DELEGATECALL
0022 PUSH1 0x02
0024 SSTORE
0025 STOP
```


> Execution Trace

```
2023-01-21T16:06:15.141788Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_ABCB_RECURSIVE.json", Total Files :: 1
2023-01-21T16:06:15.142212Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_ABCB_RECURSIVE.json"
2023-01-21T16:06:15.257667Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-21T16:06:27.605574Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-21T16:06:27.605767Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-21T16:06:27.605856Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzacebnl4qs36lv6yeufvqp2v2ulyxw7fg4lsy74npykx6rbqt7tu7you
[DEBUG] fetching parameters block: 1
2023-01-21T16:06:27.609044Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-21T16:06:27.609186Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-21T16:06:27.609238Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([135, 86, 195, 226, 17, 192, 42, 192, 25, 213, 136, 254, 18, 95, 50, 68, 155, 121, 209, 130]) }
[DEBUG] getting cid: bafy2bzacec4vpktydmelpwnsx5wnk7ddcfjbcy4p32woetpf5pywtrugromus
[DEBUG] fetching parameters block: 1
2023-01-21T16:06:27.612537Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [202]
2023-01-21T16:06:27.612678Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-21T16:06:27.612729Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([121, 46, 44, 168, 100, 157, 195, 57, 208, 185, 119, 244, 82, 48, 8, 55, 203, 168, 19, 62]) }
[DEBUG] getting cid: bafy2bzaced2l3n2nphc2xwbukvf2fiooxrsdsoj7hd2rymybae7bd7owbz76m
[DEBUG] fetching parameters block: 1
2023-01-21T16:06:27.615805Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [203]
2023-01-21T16:06:27.615962Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-21T16:06:27.617192Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-21T16:06:27.617251Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_ABCB_RECURSIVE"::Istanbul::0
2023-01-21T16:06:27.617260Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_ABCB_RECURSIVE.json"
2023-01-21T16:06:27.617270Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-21T16:06:27.617277Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 1
2023-01-21T16:06:27.620373Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6170483,
    events_root: None,
}
2023-01-21T16:06:27.620438Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-21T16:06:27.620481Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_ABCB_RECURSIVE"::Berlin::0
2023-01-21T16:06:27.620489Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_ABCB_RECURSIVE.json"
2023-01-21T16:06:27.620496Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-21T16:06:27.620504Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 1
2023-01-21T16:06:27.622689Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5269065,
    events_root: None,
}
2023-01-21T16:06:27.622738Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-21T16:06:27.622765Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_ABCB_RECURSIVE"::London::0
2023-01-21T16:06:27.622772Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_ABCB_RECURSIVE.json"
2023-01-21T16:06:27.622781Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-21T16:06:27.622787Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 1
2023-01-21T16:06:27.624946Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5269065,
    events_root: None,
}
2023-01-21T16:06:27.624996Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-21T16:06:27.625025Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_ABCB_RECURSIVE"::Merge::0
2023-01-21T16:06:27.625033Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_ABCB_RECURSIVE.json"
2023-01-21T16:06:27.625040Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-21T16:06:27.625046Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 1
2023-01-21T16:06:27.627218Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5269065,
    events_root: None,
}
2023-01-21T16:06:27.629325Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_ABCB_RECURSIVE.json"
2023-01-21T16:06:27.629585Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:12.369625281s
```