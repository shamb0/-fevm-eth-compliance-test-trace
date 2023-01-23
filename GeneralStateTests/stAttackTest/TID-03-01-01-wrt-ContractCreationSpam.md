> Status

| Status | Context |
| --- | --- |
| KO | under WASM RT context |
| TODO | under native RT context |

KO :: Execution blocked

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stAttackTest/ContractCreationSpam.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stAttackTest/ContractCreationSpam.json \
	cargo run \
	-- \
	statetest
```

> For Review

* `transaction::data` is empty | Execution Freeze

```
"transaction" : {
	"data" : [
		"0x"
	],
	"gasLimit" : [
		"0x989680"
	],
	"gasPrice" : "0x0a",
	"nonce" : "0x00",
	"secretKey" : "0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8",
	"sender" : "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
	"to" : "0x6a0a0fc761c612c340a0e98d33b37a75e5268472",
	"value" : [
		"0x00"
	]
}
```

> opcodes

```
0000 PUSH32 0x6004600c60003960046000f3600035ff00000000000000000000000000000000
0021 PUSH1 0x00
0023 MSTORE
0024 PUSH1 0x20
0026 PUSH1 0x00
0028 PUSH1 0x00
002a CREATE
002b PUSH1 0x00
002d SLOAD
002e DUP1
002f JUMPDEST
0030 PUSH1 0x01
0032 ADD
0033 DUP1
0034 PUSH1 0x00
0036 MSTORE
0037 PUSH1 0x00
0039 DUP1
003a PUSH1 0x20
003c DUP2
003d DUP1
003e DUP8
003f PUSH1 0x06
0041 CALL
0042 POP
0043 PUSH1 0x01
0045 ADD
0046 DUP1
0047 PUSH1 0x00
0049 MSTORE
004a PUSH1 0x00
004c DUP1
004d PUSH1 0x20
004f DUP2
0050 DUP1
0051 DUP8
0052 PUSH1 0x06
0054 CALL
0055 POP
0056 PUSH1 0x01
0058 ADD
0059 DUP1
005a PUSH1 0x00
005c MSTORE
005d PUSH1 0x00
005f DUP1
0060 PUSH1 0x20
0062 DUP2
0063 DUP1
0064 DUP8
0065 PUSH1 0x06
0067 CALL
0068 POP
0069 PUSH1 0x01
006b ADD
006c DUP1
006d PUSH1 0x00
006f MSTORE
0070 PUSH1 0x00
0072 DUP1
0073 PUSH1 0x20
0075 DUP2
0076 DUP1
0077 DUP8
0078 PUSH1 0x06
007a CALL
007b POP
007c PUSH1 0x01
007e ADD
007f DUP1
0080 PUSH1 0x00
0082 MSTORE
0083 PUSH1 0x00
0085 DUP1
0086 PUSH1 0x20
0088 DUP2
0089 DUP1
008a DUP8
008b PUSH1 0x06
008d CALL
008e POP
008f PUSH1 0x01
0091 ADD
0092 DUP1
0093 PUSH1 0x00
0095 MSTORE
0096 PUSH1 0x00
0098 DUP1
0099 PUSH1 0x20
009b DUP2
009c DUP1
009d DUP8
009e PUSH1 0x06
00a0 CALL
00a1 POP
00a2 PUSH1 0x01
00a4 ADD
00a5 DUP1
00a6 PUSH1 0x00
00a8 MSTORE
00a9 PUSH1 0x00
00ab DUP1
00ac PUSH1 0x20
00ae DUP2
00af DUP1
00b0 DUP8
00b1 PUSH1 0x06
00b3 CALL
00b4 POP
00b5 PUSH1 0x01
00b7 ADD
00b8 DUP1
00b9 PUSH1 0x00
00bb MSTORE
00bc PUSH1 0x00
00be DUP1
00bf PUSH1 0x20
00c1 DUP2
00c2 DUP1
00c3 DUP8
00c4 PUSH1 0x06
00c6 CALL
00c7 POP
00c8 PUSH1 0x01
00ca ADD
00cb DUP1
00cc PUSH1 0x00
00ce MSTORE
00cf PUSH1 0x00
00d1 DUP1
00d2 PUSH1 0x20
00d4 DUP2
00d5 DUP1
00d6 DUP8
00d7 PUSH1 0x06
00d9 CALL
00da POP
00db PUSH1 0x01
00dd ADD
00de DUP1
00df PUSH1 0x00
00e1 MSTORE
00e2 PUSH1 0x00
00e4 DUP1
00e5 PUSH1 0x20
00e7 DUP2
00e8 DUP1
00e9 DUP8
00ea PUSH1 0x06
00ec CALL
00ed POP
00ee PUSH1 0x01
00f0 ADD
00f1 DUP1
00f2 PUSH1 0x00
00f4 MSTORE
00f5 PUSH1 0x00
00f7 DUP1
00f8 PUSH1 0x20
00fa DUP2
00fb DUP1
00fc DUP8
00fd PUSH1 0x06
00ff CALL
0100 POP
0101 PUSH1 0x01
0103 ADD
0104 DUP1
0105 PUSH1 0x00
0107 MSTORE
0108 PUSH1 0x00
010a DUP1
010b PUSH1 0x20
010d DUP2
010e DUP1
010f DUP8
0110 PUSH1 0x06
0112 CALL
0113 POP
0114 PUSH1 0x01
0116 ADD
0117 DUP1
0118 PUSH1 0x00
011a MSTORE
011b PUSH1 0x00
011d DUP1
011e PUSH1 0x20
0120 DUP2
0121 DUP1
0122 DUP8
0123 PUSH1 0x06
0125 CALL
0126 POP
0127 PUSH1 0x01
0129 ADD
012a DUP1
012b PUSH1 0x00
012d MSTORE
012e PUSH1 0x00
0130 DUP1
0131 PUSH1 0x20
0133 DUP2
0134 DUP1
0135 DUP8
0136 PUSH1 0x06
0138 CALL
0139 POP
013a PUSH1 0x01
013c ADD
013d DUP1
013e PUSH1 0x00
0140 MSTORE
0141 PUSH1 0x00
0143 DUP1
0144 PUSH1 0x20
0146 DUP2
0147 DUP1
0148 DUP8
0149 PUSH1 0x06
014b CALL
014c POP
014d PUSH1 0x01
014f ADD
0150 DUP1
0151 PUSH1 0x00
0153 MSTORE
0154 PUSH1 0x00
0156 DUP1
0157 PUSH1 0x20
0159 DUP2
015a DUP1
015b DUP8
015c PUSH1 0x06
015e CALL
015f POP
0160 PUSH1 0x01
0162 ADD
0163 DUP1
0164 PUSH1 0x00
0166 MSTORE
0167 PUSH1 0x00
0169 DUP1
016a PUSH1 0x20
016c DUP2
016d DUP1
016e DUP8
016f PUSH1 0x06
0171 CALL
0172 POP
0173 PUSH1 0x01
0175 ADD
0176 DUP1
0177 PUSH1 0x00
0179 MSTORE
017a PUSH1 0x00
017c DUP1
017d PUSH1 0x20
017f DUP2
0180 DUP1
0181 DUP8
0182 PUSH1 0x06
0184 CALL
0185 POP
0186 PUSH1 0x01
0188 ADD
0189 DUP1
018a PUSH1 0x00
018c MSTORE
018d PUSH1 0x00
018f DUP1
0190 PUSH1 0x20
0192 DUP2
0193 DUP1
0194 DUP8
0195 PUSH1 0x06
0197 CALL
0198 POP
0199 PUSH1 0x01
019b ADD
019c DUP1
019d PUSH1 0x00
019f MSTORE
01a0 PUSH1 0x00
01a2 DUP1
01a3 PUSH1 0x20
01a5 DUP2
01a6 DUP1
01a7 DUP8
01a8 PUSH1 0x06
01aa CALL
01ab POP
01ac PUSH1 0x01
01ae ADD
01af DUP1
01b0 PUSH1 0x00
01b2 MSTORE
01b3 PUSH1 0x00
01b5 DUP1
01b6 PUSH1 0x20
01b8 DUP2
01b9 DUP1
01ba DUP8
01bb PUSH1 0x06
01bd CALL
01be POP
01bf PUSH1 0x01
01c1 ADD
01c2 DUP1
01c3 PUSH1 0x00
01c5 MSTORE
01c6 PUSH1 0x00
01c8 DUP1
01c9 PUSH1 0x20
01cb DUP2
01cc DUP1
01cd DUP8
01ce PUSH1 0x06
01d0 CALL
01d1 POP
01d2 PUSH1 0x01
01d4 ADD
01d5 DUP1
01d6 PUSH1 0x00
01d8 MSTORE
01d9 PUSH1 0x00
01db DUP1
01dc PUSH1 0x20
01de DUP2
01df DUP1
01e0 DUP8
01e1 PUSH1 0x06
01e3 CALL
01e4 POP
01e5 PUSH1 0x01
01e7 ADD
01e8 DUP1
01e9 PUSH1 0x00
01eb MSTORE
01ec PUSH1 0x00
01ee DUP1
01ef PUSH1 0x20
01f1 DUP2
01f2 DUP1
01f3 DUP8
01f4 PUSH1 0x06
01f6 CALL
01f7 POP
01f8 PUSH1 0x01
01fa ADD
01fb DUP1
01fc PUSH1 0x00
01fe MSTORE
01ff PUSH1 0x00
0201 DUP1
0202 PUSH1 0x20
0204 DUP2
0205 DUP1
0206 DUP8
0207 PUSH1 0x06
0209 CALL
020a POP
020b PUSH1 0x01
020d ADD
020e DUP1
020f PUSH1 0x00
0211 MSTORE
0212 PUSH1 0x00
0214 DUP1
0215 PUSH1 0x20
0217 DUP2
0218 DUP1
0219 DUP8
021a PUSH1 0x06
021c CALL
021d POP
021e PUSH1 0x01
0220 ADD
0221 DUP1
0222 PUSH1 0x00
0224 MSTORE
0225 PUSH1 0x00
0227 DUP1
0228 PUSH1 0x20
022a DUP2
022b DUP1
022c DUP8
022d PUSH1 0x06
022f CALL
0230 POP
0231 PUSH1 0x01
0233 ADD
0234 DUP1
0235 PUSH1 0x00
0237 MSTORE
0238 PUSH1 0x00
023a DUP1
023b PUSH1 0x20
023d DUP2
023e DUP1
023f DUP8
0240 PUSH1 0x06
0242 CALL
0243 POP
0244 PUSH1 0x01
0246 ADD
0247 DUP1
0248 PUSH1 0x00
024a MSTORE
024b PUSH1 0x00
024d DUP1
024e PUSH1 0x20
0250 DUP2
0251 DUP1
0252 DUP8
0253 PUSH1 0x06
0255 CALL
0256 POP
0257 PUSH1 0x01
0259 ADD
025a DUP1
025b PUSH1 0x00
025d MSTORE
025e PUSH1 0x00
0260 DUP1
0261 PUSH1 0x20
0263 DUP2
0264 DUP1
0265 DUP8
0266 PUSH1 0x06
0268 CALL
0269 POP
026a PUSH1 0x01
026c ADD
026d DUP1
026e PUSH1 0x00
0270 MSTORE
0271 PUSH1 0x00
0273 DUP1
0274 PUSH1 0x20
0276 DUP2
0277 DUP1
0278 DUP8
0279 PUSH1 0x06
027b CALL
027c POP
027d PUSH1 0x01
027f ADD
0280 DUP1
0281 PUSH1 0x00
0283 MSTORE
0284 PUSH1 0x00
0286 DUP1
0287 PUSH1 0x20
0289 DUP2
028a DUP1
028b DUP8
028c PUSH1 0x06
028e CALL
028f POP
0290 PUSH1 0x01
0292 ADD
0293 DUP1
0294 PUSH1 0x00
0296 MSTORE
0297 PUSH1 0x00
0299 DUP1
029a PUSH1 0x20
029c DUP2
029d DUP1
029e DUP8
029f PUSH1 0x06
02a1 CALL
02a2 POP
02a3 PUSH1 0x01
02a5 ADD
02a6 DUP1
02a7 PUSH1 0x00
02a9 MSTORE
02aa PUSH1 0x00
02ac DUP1
02ad PUSH1 0x20
02af DUP2
02b0 DUP1
02b1 DUP8
02b2 PUSH1 0x06
02b4 CALL
02b5 POP
02b6 PUSH1 0x01
02b8 ADD
02b9 DUP1
02ba PUSH1 0x00
02bc MSTORE
02bd PUSH1 0x00
02bf DUP1
02c0 PUSH1 0x20
02c2 DUP2
02c3 DUP1
02c4 DUP8
02c5 PUSH1 0x06
02c7 CALL
02c8 POP
02c9 PUSH1 0x01
02cb ADD
02cc DUP1
02cd PUSH1 0x00
02cf MSTORE
02d0 PUSH1 0x00
02d2 DUP1
02d3 PUSH1 0x20
02d5 DUP2
02d6 DUP1
02d7 DUP8
02d8 PUSH1 0x06
02da CALL
02db POP
02dc PUSH1 0x01
02de ADD
02df DUP1
02e0 PUSH1 0x00
02e2 MSTORE
02e3 PUSH1 0x00
02e5 DUP1
02e6 PUSH1 0x20
02e8 DUP2
02e9 DUP1
02ea DUP8
02eb PUSH1 0x06
02ed CALL
02ee POP
02ef PUSH1 0x01
02f1 ADD
02f2 DUP1
02f3 PUSH1 0x00
02f5 MSTORE
02f6 PUSH1 0x00
02f8 DUP1
02f9 PUSH1 0x20
02fb DUP2
02fc DUP1
02fd DUP8
02fe PUSH1 0x06
0300 CALL
0301 POP
0302 PUSH1 0x01
0304 ADD
0305 DUP1
0306 PUSH1 0x00
0308 MSTORE
0309 PUSH1 0x00
030b DUP1
030c PUSH1 0x20
030e DUP2
030f DUP1
0310 DUP8
0311 PUSH1 0x06
0313 CALL
0314 POP
0315 PUSH1 0x01
0317 ADD
0318 DUP1
0319 PUSH1 0x00
031b MSTORE
031c PUSH1 0x00
031e DUP1
031f PUSH1 0x20
0321 DUP2
0322 DUP1
0323 DUP8
0324 PUSH1 0x06
0326 CALL
0327 POP
0328 GAS
0329 PUSH2 0x6000
032c LT
032d PUSH3 0x00002f
0331 JUMPI
0332 PUSH1 0x00
0334 SSTORE
```

> Execution Trace

```
warning: bundle=/home/popoyi/dscbox/sun/ws-020-blocks/ws-030-filecoin-project/dev-030-01-fvm/fevm-eth-compliance-test/target/debug/build/fil_builtin_actors_bundle-6f26db190694f93a/out/bundle/bundle.car
    Finished dev [unoptimized + debuginfo] target(s) in 0.20s
     Running `target/debug/evm_eth_compliance statetest`
2023-01-20T14:38:43.889524Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stAttackTest/ContractCreationSpam.json", Total Files :: 1
2023-01-20T14:38:43.889996Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stAttackTest/ContractCreationSpam.json"
2023-01-20T14:38:44.036576Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [106, 10, 15, 199, 97, 198, 18, 195, 64, 160, 233, 141, 51, 179, 122, 117, 229, 38, 132, 114, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-20T14:38:56.067797Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-20T14:38:56.068155Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T14:38:56.068241Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzaceayqd2eqzgkz6dldpbpcygx5zduakhzhlkiktnhxqayug72vlkzcm
[DEBUG] fetching parameters block: 1
2023-01-20T14:38:56.071346Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-20T14:38:56.071514Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T14:38:56.072763Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-20T14:38:56.072839Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ContractCreationSpam"::Istanbul::0
2023-01-20T14:38:56.072854Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stAttackTest/ContractCreationSpam.json"
2023-01-20T14:38:56.072868Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T14:38:56.072880Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [204, 140, 122, 132, 212, 242, 135, 36, 65, 73, 159, 167, 43, 72, 189, 69, 176, 57, 35, 171, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
[DEBUG] getting cid: bafy2bzacec3rwabjb2c66wqavdesx62oho67ckwbjo3mtamnd3wyknmjgnpae
[DEBUG] fetching parameters block: 1
```

> Execution Trace with [Patch](https://github.com/shamb0/fevm-eth-compliance-test/pull/1)

```
  Compiling evm_eth_compliance v10.0.0-alpha.1 (/home/popoyi/dscbox/sun/ws-020-blocks/ws-030-filecoin-project/dev-030-01-fvm/fevm-eth-compliance-test)
    Finished release [optimized] target(s) in 2m 05s
     Running `target/release/evm_eth_compliance statetest`
2023-01-23T09:52:34.355683Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stAttackTest/ContractCreationSpam.json", Total Files :: 1
2023-01-23T09:52:34.355946Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stAttackTest/ContractCreationSpam.json"
2023-01-23T09:52:34.384983Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T09:52:34.385225Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T09:52:34.385231Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T09:52:34.385290Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T09:52:34.385366Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-23T09:52:34.385371Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ContractCreationSpam"::Istanbul::0
2023-01-23T09:52:34.385377Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stAttackTest/ContractCreationSpam.json"
2023-01-23T09:52:34.385383Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T09:52:34.385386Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [204, 140, 122, 132, 212, 242, 135, 36, 65, 73, 159, 167, 43, 72, 189, 69, 176, 57, 35, 171, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
flame^C^C
```

One more observation is Use-case, trying to drain out the system resource. 78% cpu is consumed & only 1.4GB of Ram is left

**After Launching the Use-Case**

![](https://i.imgur.com/aqDtIOA.png)

**Average system load**

![](https://i.imgur.com/b5lpFq7.png)
