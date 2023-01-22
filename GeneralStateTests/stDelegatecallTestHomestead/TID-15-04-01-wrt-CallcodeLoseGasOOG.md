> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| KO | under native RT context |

* KO :: [FEVM | Eth Compliance Test | Hit with stack overflow error · Issue #1437 · filecoin-project/ref-fvm](https://github.com/filecoin-project/ref-fvm/issues/1437)

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stDelegatecallTestHomestead/CallcodeLoseGasOOG.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/CallcodeLoseGasOOG.json \
	cargo run \
	-- \
	statetest
```

> For Review

- Execution looks OK (no stack overflow), use-case has recursive call to self contract using `DELEGATECALL`, stack depth is grow looks OK. Better to have opcode review & fevm execution control flow trace & muted state changed values.

> Opcodes


@0xbbbf5374fce5edbc8e2a8697c15331677e6ebf0b

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
0011 PUSH20 0xbbbf5374fce5edbc8e2a8697c15331677e6ebf0b
0026 PUSH3 0x0186a0
002a PUSH1 0x00
002c SLOAD
002d MUL
002e PUSH1 0x01
0030 ADD
0031 DELEGATECALL
0032 PUSH1 0x01
0034 SSTORE
0035 PUSH2 0x03e8
0038 PUSH1 0x00
003a SLOAD
003b MUL
003c PUSH1 0x01
003e ADD
003f PUSH1 0x02
0041 SSTORE
0042 STOP
```

> Execution Trace

```
2023-01-22T07:25:37.640636Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/CallcodeLoseGasOOG.json", Total Files :: 1
2023-01-22T07:25:37.641094Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/CallcodeLoseGasOOG.json"
2023-01-22T07:25:37.758660Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-22T07:25:49.984712Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-22T07:25:49.984914Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T07:25:49.985008Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [170, 175, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzacecsquj7xh4vk2t3fxpfxek3wh4jdtmd7u5en66azvnwf7l4u47cl6
[DEBUG] fetching parameters block: 1
2023-01-22T07:25:49.988288Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-22T07:25:49.988437Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T07:25:49.988490Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [187, 191, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([135, 86, 195, 226, 17, 192, 42, 192, 25, 213, 136, 254, 18, 95, 50, 68, 155, 121, 209, 130]) }
[DEBUG] getting cid: bafy2bzaceb7pob5r5lguldkys4zw5fpacadp3ik6sne7sskcpcby45ploebw4
[DEBUG] fetching parameters block: 1
2023-01-22T07:25:49.991810Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [202]
2023-01-22T07:25:49.991974Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T07:25:49.993178Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-22T07:25:49.993231Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallcodeLoseGasOOG"::Istanbul::0
2023-01-22T07:25:49.993241Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/CallcodeLoseGasOOG.json"
2023-01-22T07:25:49.993253Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T07:25:49.993262Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
2023-01-22T07:25:49.995022Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5290243,
    events_root: None,
}
2023-01-22T07:25:49.995066Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-22T07:25:49.995093Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallcodeLoseGasOOG"::Istanbul::0
2023-01-22T07:25:49.995101Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/CallcodeLoseGasOOG.json"
2023-01-22T07:25:49.995110Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T07:25:49.995118Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
2023-01-22T07:25:49.996726Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6455918,
    events_root: None,
}
2023-01-22T07:25:49.996768Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-22T07:25:49.996795Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallcodeLoseGasOOG"::Berlin::0
2023-01-22T07:25:49.996803Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/CallcodeLoseGasOOG.json"
2023-01-22T07:25:49.996812Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T07:25:49.996820Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
2023-01-22T07:25:49.998441Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6555918,
    events_root: None,
}
2023-01-22T07:25:49.998482Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-22T07:25:49.998509Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallcodeLoseGasOOG"::Berlin::0
2023-01-22T07:25:49.998517Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/CallcodeLoseGasOOG.json"
2023-01-22T07:25:49.998526Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T07:25:49.998534Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
2023-01-22T07:25:50.000119Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6655918,
    events_root: None,
}
2023-01-22T07:25:50.000160Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-22T07:25:50.000187Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallcodeLoseGasOOG"::London::0
2023-01-22T07:25:50.000195Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/CallcodeLoseGasOOG.json"
2023-01-22T07:25:50.000205Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T07:25:50.000213Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
2023-01-22T07:25:50.002061Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6755918,
    events_root: None,
}
2023-01-22T07:25:50.002106Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-22T07:25:50.002133Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallcodeLoseGasOOG"::London::0
2023-01-22T07:25:50.002142Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/CallcodeLoseGasOOG.json"
2023-01-22T07:25:50.002151Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T07:25:50.002159Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 1
2023-01-22T07:25:50.004113Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6855918,
    events_root: None,
}
2023-01-22T07:25:50.004166Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-22T07:25:50.004200Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallcodeLoseGasOOG"::Merge::0
2023-01-22T07:25:50.004207Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/CallcodeLoseGasOOG.json"
2023-01-22T07:25:50.004215Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T07:25:50.004221Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 1
2023-01-22T07:25:50.006142Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6955918,
    events_root: None,
}
2023-01-22T07:25:50.006184Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-22T07:25:50.006209Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallcodeLoseGasOOG"::Merge::0
2023-01-22T07:25:50.006216Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/CallcodeLoseGasOOG.json"
2023-01-22T07:25:50.006223Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-22T07:25:50.006229Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 1
2023-01-22T07:25:50.008101Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7055918,
    events_root: None,
}
2023-01-22T07:25:50.010417Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stDelegatecallTestHomestead/CallcodeLoseGasOOG.json"
2023-01-22T07:25:50.010783Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:12.249510074s
```
