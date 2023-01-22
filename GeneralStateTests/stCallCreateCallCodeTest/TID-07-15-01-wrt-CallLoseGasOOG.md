> Status

| Status | Context |
| --- | --- |
| KO | under WASM RT context |
| KO | under native RT context |


* KO :: [FEVM | Eth Compliance Test | Hit with stack overflow error · Issue #1437 · filecoin-project/ref-fvm](https://github.com/filecoin-project/ref-fvm/issues/1437)

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCallCreateCallCodeTest/CallLoseGasOOG.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/CallLoseGasOOG.json \
	cargo run \
	-- \
	statetest
```

> For Review

* No Stack overflow, but Recursive `Call` not happening. opcode needs to be reviewed.

> Opcodes

```
0000 PUSH1 0x01
0002 PUSH1 0x00
0004 SLOAD
0005 ADD
0006 PUSH1 0x00
0008 SSTORE
0009 PUSH1 0x00
000b PUSH1 0x00
000d PUSH1 0x00
000f PUSH1 0x00
0011 PUSH1 0x00
0013 PUSH20 0xbbbf5374fce5edbc8e2a8697c15331677e6ebf0b
0028 PUSH3 0x0186a0
002c PUSH1 0x00
002e SLOAD
002f MUL
0030 PUSH1 0x01
0032 ADD
0033 CALL
0034 PUSH1 0x01
0036 SSTORE
0037 PUSH2 0x03e8
003a PUSH1 0x00
003c SLOAD
003d MUL
003e PUSH1 0x01
0040 ADD
0041 PUSH1 0x02
0043 SSTORE
0044 STOP
```

> Execution Trace

```
2023-01-21T11:56:30.191434Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/CallLoseGasOOG.json", Total Files :: 1
2023-01-21T11:56:30.191928Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/CallLoseGasOOG.json"
2023-01-21T11:56:30.299226Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-21T11:56:42.414873Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-21T11:56:42.415055Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-21T11:56:42.415143Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [170, 175, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzacecsquj7xh4vk2t3fxpfxek3wh4jdtmd7u5en66azvnwf7l4u47cl6
[DEBUG] fetching parameters block: 1
2023-01-21T11:56:42.418309Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-21T11:56:42.418448Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-21T11:56:42.418495Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [187, 191, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([135, 86, 195, 226, 17, 192, 42, 192, 25, 213, 136, 254, 18, 95, 50, 68, 155, 121, 209, 130]) }
[DEBUG] getting cid: bafy2bzaceb7pob5r5lguldkys4zw5fpacadp3ik6sne7sskcpcby45ploebw4
[DEBUG] fetching parameters block: 1
2023-01-21T11:56:42.421595Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [202]
2023-01-21T11:56:42.421737Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-21T11:56:42.423077Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-21T11:56:42.423149Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallLoseGasOOG"::Istanbul::0
2023-01-21T11:56:42.423165Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/CallLoseGasOOG.json"
2023-01-21T11:56:42.423178Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-21T11:56:42.423186Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-21T11:56:42.425241Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4340254,
    events_root: None,
}
2023-01-21T11:56:42.425300Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-21T11:56:42.425350Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallLoseGasOOG"::Berlin::0
2023-01-21T11:56:42.425358Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/CallLoseGasOOG.json"
2023-01-21T11:56:42.425365Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-21T11:56:42.425371Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-21T11:56:42.426650Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5507586,
    events_root: None,
}
2023-01-21T11:56:42.426686Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-21T11:56:42.426713Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallLoseGasOOG"::London::0
2023-01-21T11:56:42.426720Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/CallLoseGasOOG.json"
2023-01-21T11:56:42.426727Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-21T11:56:42.426734Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-21T11:56:42.427932Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5607586,
    events_root: None,
}
2023-01-21T11:56:42.427968Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-21T11:56:42.427994Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallLoseGasOOG"::Merge::0
2023-01-21T11:56:42.428001Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/CallLoseGasOOG.json"
2023-01-21T11:56:42.428008Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-21T11:56:42.428016Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-21T11:56:42.429194Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5707586,
    events_root: None,
}
2023-01-21T11:56:42.431373Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/CallLoseGasOOG.json"
2023-01-21T11:56:42.431706Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:12.130026423s
```
