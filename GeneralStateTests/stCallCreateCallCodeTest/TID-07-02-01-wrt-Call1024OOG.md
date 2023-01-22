> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| KO | under native RT context |

* KO :: [FEVM | Eth Compliance Test | Hit with stack overflow error · Issue #1437 · filecoin-project/ref-fvm](https://github.com/filecoin-project/ref-fvm/issues/1437)

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json \
	cargo run \
	-- \
	statetest
```

> For Review

* Execution looks OK, getting terminated instead of stack overflow. I hope stack depth upper limit is based on message `gasLimit`, Plz correct me if I'm wrong.

* Recursive `Call` with single stack frame structure, good to review the opcode control flow.

```
"transaction" : {
	"data" : [
		"0x"
	],
	"gasLimit" : [
		"0xc8353a",
		"0x8e397a",
		"0xefe17a",
		"0xab375a"
	],
	"gasPrice" : "0x0a",
	"nonce" : "0x00",
	"secretKey" : "0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8",
	"sender" : "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
	"to" : "0xbbbf5374fce5edbc8e2a8697c15331677e6ebf0b",
	"value" : [
		"0x0a"
	]
}
```

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
0028 PUSH2 0x0401
002b PUSH1 0x00
002d SLOAD
002e DIV
002f PUSH1 0x01
0031 SUB
0032 PUSH2 0x2710
0035 GAS
0036 SUB
0037 MUL
0038 CALL
0039 PUSH1 0x01
003b SSTORE
003c PUSH2 0x03e8
003f PUSH1 0x00
0041 SLOAD
0042 MUL
0043 PUSH1 0x01
0045 ADD
0046 PUSH1 0x02
0048 SSTORE
0049 STOP
```

> Execution Trace

```
2023-01-21T11:19:17.892539Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json", Total Files :: 1
2023-01-21T11:19:17.893019Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json"
2023-01-21T11:19:18.144623Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-21T11:19:29.756118Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-21T11:19:29.756302Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-21T11:19:29.756390Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [170, 175, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzacecsquj7xh4vk2t3fxpfxek3wh4jdtmd7u5en66azvnwf7l4u47cl6
[DEBUG] fetching parameters block: 1
2023-01-21T11:19:29.759487Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-21T11:19:29.759627Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-21T11:19:29.759676Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [187, 191, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([135, 86, 195, 226, 17, 192, 42, 192, 25, 213, 136, 254, 18, 95, 50, 68, 155, 121, 209, 130]) }
[DEBUG] getting cid: bafy2bzaceb7pob5r5lguldkys4zw5fpacadp3ik6sne7sskcpcby45ploebw4
[DEBUG] fetching parameters block: 1
2023-01-21T11:19:29.762595Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [202]
2023-01-21T11:19:29.762733Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-21T11:19:29.764159Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-21T11:19:29.764224Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::Istanbul::0
2023-01-21T11:19:29.764238Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json"
2023-01-21T11:19:29.764249Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-21T11:19:29.764258Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-21T11:19:30.702417Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3851079730,
    events_root: None,
}
2023-01-21T11:19:30.716709Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-21T11:19:30.716793Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::Istanbul::0
2023-01-21T11:19:30.716801Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json"
2023-01-21T11:19:30.716809Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-21T11:19:30.716816Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-21T11:19:30.721368Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6066019,
    events_root: None,
}
2023-01-21T11:19:30.721420Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-21T11:19:30.721461Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::Istanbul::0
2023-01-21T11:19:30.721469Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json"
2023-01-21T11:19:30.721476Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-21T11:19:30.721482Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-21T11:19:30.722546Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5333298,
    events_root: None,
}
2023-01-21T11:19:30.722578Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-21T11:19:30.722604Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::Istanbul::0
2023-01-21T11:19:30.722611Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json"
2023-01-21T11:19:30.722617Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-21T11:19:30.722623Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-21T11:19:30.723666Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5333298,
    events_root: None,
}
2023-01-21T11:19:30.723702Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-21T11:19:30.723728Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::Berlin::0
2023-01-21T11:19:30.723734Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json"
2023-01-21T11:19:30.723741Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-21T11:19:30.723747Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-21T11:19:30.724802Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5333298,
    events_root: None,
}
2023-01-21T11:19:30.724834Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-21T11:19:30.724860Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::Berlin::0
2023-01-21T11:19:30.724867Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json"
2023-01-21T11:19:30.724873Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-21T11:19:30.724879Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-21T11:19:30.725921Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5333298,
    events_root: None,
}
2023-01-21T11:19:30.725954Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-21T11:19:30.725982Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::Berlin::0
2023-01-21T11:19:30.725989Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json"
2023-01-21T11:19:30.725996Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-21T11:19:30.726002Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-21T11:19:30.727039Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5333298,
    events_root: None,
}
2023-01-21T11:19:30.727071Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-21T11:19:30.727096Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::Berlin::0
2023-01-21T11:19:30.727103Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json"
2023-01-21T11:19:30.727110Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-21T11:19:30.727115Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-21T11:19:30.728167Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5333298,
    events_root: None,
}
2023-01-21T11:19:30.728201Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-21T11:19:30.728226Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::London::0
2023-01-21T11:19:30.728233Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json"
2023-01-21T11:19:30.728240Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-21T11:19:30.728246Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-21T11:19:30.729299Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5333298,
    events_root: None,
}
2023-01-21T11:19:30.729332Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-21T11:19:30.729358Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::London::0
2023-01-21T11:19:30.729365Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json"
2023-01-21T11:19:30.729371Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-21T11:19:30.729377Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-21T11:19:30.730421Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5333298,
    events_root: None,
}
2023-01-21T11:19:30.730453Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-21T11:19:30.730478Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::London::0
2023-01-21T11:19:30.730485Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json"
2023-01-21T11:19:30.730492Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-21T11:19:30.730498Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-21T11:19:30.731538Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5333298,
    events_root: None,
}
2023-01-21T11:19:30.731570Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-21T11:19:30.731596Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::London::0
2023-01-21T11:19:30.731602Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json"
2023-01-21T11:19:30.731609Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-21T11:19:30.731615Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-21T11:19:30.732660Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5333298,
    events_root: None,
}
2023-01-21T11:19:30.732693Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-21T11:19:30.732719Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::Merge::0
2023-01-21T11:19:30.732726Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json"
2023-01-21T11:19:30.732732Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-21T11:19:30.732739Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-21T11:19:30.733786Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5333298,
    events_root: None,
}
2023-01-21T11:19:30.733819Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-21T11:19:30.733845Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::Merge::0
2023-01-21T11:19:30.733851Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json"
2023-01-21T11:19:30.733858Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-21T11:19:30.733864Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-21T11:19:30.734908Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5333298,
    events_root: None,
}
2023-01-21T11:19:30.734940Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-21T11:19:30.734966Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::Merge::0
2023-01-21T11:19:30.734973Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json"
2023-01-21T11:19:30.734979Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-21T11:19:30.734985Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-21T11:19:30.736029Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5333298,
    events_root: None,
}
2023-01-21T11:19:30.736061Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-21T11:19:30.736087Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call1024OOG"::Merge::0
2023-01-21T11:19:30.736094Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json"
2023-01-21T11:19:30.736101Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-21T11:19:30.736106Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-21T11:19:30.737142Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5333298,
    events_root: None,
}
2023-01-21T11:19:30.749626Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stCallCreateCallCodeTest/Call1024OOG.json"
2023-01-21T11:19:30.751050Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:12.592576235s
```