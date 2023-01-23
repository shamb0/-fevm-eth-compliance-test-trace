
> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stBadOpcode/undefinedOpcodeFirstByte.json#L6


> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stBadOpcode/undefinedOpcodeFirstByte.json \
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
		"0x042c1d80"
	],
	"gasPrice" : "0x0a",
	"nonce" : "0x00",
	"secretKey" : "0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8",
	"sender" : "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
	"to" : "0xb94f5374fce5edbc8e2a8697c15331677e6ebf0b",
	"value" : [
		"0x00"
	]
}
```

> Opcodes

```
0000 PUSH1 0x00
0002 JUMPDEST
0003 PUSH2 0x0100
0006 DUP2
0007 LT
0008 ISZERO
0009 PUSH1 0x33
000b JUMPI
000c DUP1
000d PUSH1 0x98
000f SHL
0010 PUSH1 0x00
0012 PUSH1 0x00
0014 PUSH1 0x00
0016 PUSH1 0x00
0018 PUSH1 0x00
001a DUP6
001b PUSH2 0x2710
001e CALL
001f ISZERO
0020 PUSH1 0x27
0022 JUMPI
0023 PUSH1 0x01
0025 DUP3
0026 SSTORE
0027 JUMPDEST
0028 POP
0029 JUMPDEST
002a PUSH1 0x01
002c DUP2
002d ADD
002e SWAP1
002f POP
0030 PUSH1 0x02
0032 JUMP
0033 JUMPDEST
0034 POP
0035 PUSH1 0x01
0037 PUSH2 0x0100
003a SSTORE
```

> Execution Trace

```
2023-01-23T06:42:34.373412Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stBadOpcode/undefinedOpcodeFirstByte.json", Total Files :: 1
2023-01-23T06:42:34.373864Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stBadOpcode/undefinedOpcodeFirstByte.json"
2023-01-23T06:42:34.718087Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-23T06:42:34.723603Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.723619Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-23T06:42:34.724787Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.724800Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-23T06:42:34.726087Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.726101Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-23T06:42:34.727309Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.727328Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-23T06:42:34.728547Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.728562Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-23T06:42:34.729911Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.729925Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 6
2023-01-23T06:42:34.731157Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.731170Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 7
2023-01-23T06:42:34.732202Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.732219Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 8
2023-01-23T06:42:34.733260Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.733274Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 9
2023-01-23T06:42:34.734405Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.734419Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 10
2023-01-23T06:42:34.735395Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.735409Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 11
2023-01-23T06:42:34.736433Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.736447Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 12
2023-01-23T06:42:34.737429Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.737443Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 13
2023-01-23T06:42:34.738414Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.738427Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 14
2023-01-23T06:42:34.739589Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.739608Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 15
2023-01-23T06:42:34.740690Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.740703Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 16
2023-01-23T06:42:34.741827Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.741845Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 17
2023-01-23T06:42:34.743226Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.743245Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 18
2023-01-23T06:42:34.744514Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.744534Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 19
2023-01-23T06:42:34.745530Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.745546Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 20
2023-01-23T06:42:34.746550Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.746564Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 21
2023-01-23T06:42:34.747789Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.747803Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 22
2023-01-23T06:42:34.749162Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.749176Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 23
2023-01-23T06:42:34.750399Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.750414Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 24
2023-01-23T06:42:34.751403Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.751417Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 25
2023-01-23T06:42:34.752761Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.752778Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 26
2023-01-23T06:42:34.753806Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.753820Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 27
2023-01-23T06:42:34.754784Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.754797Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 28
2023-01-23T06:42:34.755987Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.756009Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 29
2023-01-23T06:42:34.757190Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.757203Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 30
2023-01-23T06:42:34.758221Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.758236Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 31
2023-01-23T06:42:34.759377Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.759392Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 32
2023-01-23T06:42:34.760547Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.760560Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 33
2023-01-23T06:42:34.761542Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.761556Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 34
2023-01-23T06:42:34.762709Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.762723Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 35
2023-01-23T06:42:34.763878Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.763897Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 36
2023-01-23T06:42:34.764954Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.764968Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 37
2023-01-23T06:42:34.765985Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.766000Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 38
2023-01-23T06:42:34.766973Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.766987Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 39
2023-01-23T06:42:34.767986Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.768001Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 40
2023-01-23T06:42:34.769039Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.769054Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 41
2023-01-23T06:42:34.770051Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.770065Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 42
2023-01-23T06:42:34.771130Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.771144Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 43
2023-01-23T06:42:34.772458Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.772472Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 44
2023-01-23T06:42:34.773572Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.773587Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 45
2023-01-23T06:42:34.774830Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.774848Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 46
2023-01-23T06:42:34.775897Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.775911Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 47
2023-01-23T06:42:34.777095Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.777109Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 48
2023-01-23T06:42:34.778290Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.778308Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 49
2023-01-23T06:42:34.779336Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.779350Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 50
2023-01-23T06:42:34.780343Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.780356Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 51
2023-01-23T06:42:34.781332Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.781346Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 52
2023-01-23T06:42:34.782333Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.782347Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 53
2023-01-23T06:42:34.783414Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.783427Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 54
2023-01-23T06:42:34.784424Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.784438Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 55
2023-01-23T06:42:34.785490Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.785509Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 56
2023-01-23T06:42:34.786589Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.786618Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 57
2023-01-23T06:42:34.787616Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.787629Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 58
2023-01-23T06:42:34.788828Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.788841Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 59
2023-01-23T06:42:34.789874Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.789887Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 60
2023-01-23T06:42:34.790891Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.790907Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 61
2023-01-23T06:42:34.791913Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.791927Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 62
2023-01-23T06:42:34.792979Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.792992Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 63
2023-01-23T06:42:34.794266Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.794279Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 64
2023-01-23T06:42:34.795313Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.795328Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 65
2023-01-23T06:42:34.796334Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.796349Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 66
2023-01-23T06:42:34.797383Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.797397Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 67
2023-01-23T06:42:34.798550Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.798567Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 68
2023-01-23T06:42:34.799467Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.799483Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 69
2023-01-23T06:42:34.800498Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.800513Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 70
2023-01-23T06:42:34.801606Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.801620Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 71
2023-01-23T06:42:34.802690Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.802704Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 72
2023-01-23T06:42:34.803766Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.803780Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 73
2023-01-23T06:42:34.804856Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.804870Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 74
2023-01-23T06:42:34.805925Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.805942Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 75
2023-01-23T06:42:34.807022Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.807037Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 76
2023-01-23T06:42:34.808121Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.808135Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 77
2023-01-23T06:42:34.809096Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.809110Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 78
2023-01-23T06:42:34.810177Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.810192Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 79
2023-01-23T06:42:34.811204Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.811218Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 80
2023-01-23T06:42:34.812216Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.812230Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 81
2023-01-23T06:42:34.813322Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.813338Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 82
2023-01-23T06:42:34.814415Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.814432Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 83
2023-01-23T06:42:34.815455Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.815469Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 84
2023-01-23T06:42:34.816563Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.816577Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 85
2023-01-23T06:42:34.817694Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.817709Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 86
2023-01-23T06:42:34.818686Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.818699Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 87
2023-01-23T06:42:34.819727Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.819741Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 88
2023-01-23T06:42:34.820777Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.820791Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 89
2023-01-23T06:42:34.822068Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.822083Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 90
2023-01-23T06:42:34.823094Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.823108Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 91
2023-01-23T06:42:34.824082Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.824096Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 92
2023-01-23T06:42:34.825162Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.825176Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 93
2023-01-23T06:42:34.826527Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.826547Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 94
2023-01-23T06:42:34.827757Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.827774Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 95
2023-01-23T06:42:34.828815Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.828829Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 96
2023-01-23T06:42:34.829816Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.829832Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 97
2023-01-23T06:42:34.830817Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.830834Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 98
2023-01-23T06:42:34.832009Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.832026Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 99
2023-01-23T06:42:34.833253Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.833267Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 100
2023-01-23T06:42:34.834313Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.834327Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 101
2023-01-23T06:42:34.835575Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.835589Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 102
2023-01-23T06:42:34.836722Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.836736Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 103
2023-01-23T06:42:34.837773Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.837788Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 104
2023-01-23T06:42:34.838837Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.838851Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 105
2023-01-23T06:42:34.839875Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.839888Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 106
2023-01-23T06:42:34.840945Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.840962Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 107
2023-01-23T06:42:34.842354Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.842371Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 108
2023-01-23T06:42:34.843625Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.843641Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 109
2023-01-23T06:42:34.844812Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.844826Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 110
2023-01-23T06:42:34.845908Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.845923Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 111
2023-01-23T06:42:34.847230Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.847248Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 112
2023-01-23T06:42:34.848452Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.848498Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 113
2023-01-23T06:42:34.849551Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.849565Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 114
2023-01-23T06:42:34.850554Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.850568Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 115
2023-01-23T06:42:34.851609Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.851623Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 116
2023-01-23T06:42:34.852604Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.852618Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 117
2023-01-23T06:42:34.853786Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.853801Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 118
2023-01-23T06:42:34.854839Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.854854Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 119
2023-01-23T06:42:34.855844Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.855858Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 120
2023-01-23T06:42:34.856898Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.856912Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 121
2023-01-23T06:42:34.857876Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.857890Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 122
2023-01-23T06:42:34.858996Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.859011Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 123
2023-01-23T06:42:34.860055Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.860070Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 124
2023-01-23T06:42:34.861109Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.861124Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 125
2023-01-23T06:42:34.862177Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.862192Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 126
2023-01-23T06:42:34.863250Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.863264Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 127
2023-01-23T06:42:34.864317Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.864334Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 128
2023-01-23T06:42:34.865475Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.865488Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 129
2023-01-23T06:42:34.866538Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.866552Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 130
2023-01-23T06:42:34.867615Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.867628Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 131
2023-01-23T06:42:34.868645Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.868659Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 132
2023-01-23T06:42:34.869707Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.869720Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 133
2023-01-23T06:42:34.870799Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.870816Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 134
2023-01-23T06:42:34.871932Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.871946Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 135
2023-01-23T06:42:34.872997Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.873010Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 136
2023-01-23T06:42:34.874000Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.874014Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 137
2023-01-23T06:42:34.874984Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.874998Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 138
2023-01-23T06:42:34.876040Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.876054Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 139
2023-01-23T06:42:34.877129Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.877142Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 140
2023-01-23T06:42:34.878200Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.878214Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 141
2023-01-23T06:42:34.879260Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.879273Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 142
2023-01-23T06:42:34.880318Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.880331Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 143
2023-01-23T06:42:34.881341Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.881354Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 144
2023-01-23T06:42:34.882427Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.882441Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 145
2023-01-23T06:42:34.883552Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.883567Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 146
2023-01-23T06:42:34.884685Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.884700Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 147
2023-01-23T06:42:34.885734Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.885748Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 148
2023-01-23T06:42:34.886841Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.886855Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 149
2023-01-23T06:42:34.887925Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.887939Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 150
2023-01-23T06:42:34.888919Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.888933Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 151
2023-01-23T06:42:34.889939Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.889954Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 152
2023-01-23T06:42:34.890965Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.890980Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 153
2023-01-23T06:42:34.891974Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.891988Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 154
2023-01-23T06:42:34.892917Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.892931Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 155
2023-01-23T06:42:34.894035Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.894049Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 156
2023-01-23T06:42:34.895069Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.895083Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 157
2023-01-23T06:42:34.896087Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.896104Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 158
2023-01-23T06:42:34.897194Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.897208Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 159
2023-01-23T06:42:34.898318Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.898333Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 160
2023-01-23T06:42:34.899400Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.899415Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 161
2023-01-23T06:42:34.900485Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.900500Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 162
2023-01-23T06:42:34.901728Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.901743Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 163
2023-01-23T06:42:34.902748Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.902762Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 164
2023-01-23T06:42:34.903838Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.903852Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 165
2023-01-23T06:42:34.904886Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.904901Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 166
2023-01-23T06:42:34.906003Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.906018Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 167
2023-01-23T06:42:34.907118Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.907134Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 168
2023-01-23T06:42:34.908201Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.908215Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 169
2023-01-23T06:42:34.909223Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.909238Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 170
2023-01-23T06:42:34.910393Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.910410Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 171
2023-01-23T06:42:34.911408Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.911422Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 172
2023-01-23T06:42:34.912527Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.912542Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 173
2023-01-23T06:42:34.913582Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.913597Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 174
2023-01-23T06:42:34.914766Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.914780Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 175
2023-01-23T06:42:34.915734Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.915748Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 176
2023-01-23T06:42:34.916742Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.916756Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 177
2023-01-23T06:42:34.917743Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.917757Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 178
2023-01-23T06:42:34.918786Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.918801Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 179
2023-01-23T06:42:34.920237Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.920251Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 180
2023-01-23T06:42:34.921261Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.921276Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 181
2023-01-23T06:42:34.922308Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.922323Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 182
2023-01-23T06:42:34.923434Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.923448Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 183
2023-01-23T06:42:34.924430Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.924444Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 184
2023-01-23T06:42:34.925615Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.925630Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 185
2023-01-23T06:42:34.926692Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.926707Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 186
2023-01-23T06:42:34.927891Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.927907Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 187
2023-01-23T06:42:34.928996Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.929012Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 188
2023-01-23T06:42:34.930022Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.930037Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 189
2023-01-23T06:42:34.931046Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.931061Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 190
2023-01-23T06:42:34.932153Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.932167Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 191
2023-01-23T06:42:34.933186Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.933201Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 192
2023-01-23T06:42:34.934203Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.934218Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 193
2023-01-23T06:42:34.935314Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.935328Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 194
2023-01-23T06:42:34.936350Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.936366Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 195
2023-01-23T06:42:34.937484Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.937503Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 196
2023-01-23T06:42:34.938617Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.938632Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 197
2023-01-23T06:42:34.939674Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.939688Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 198
2023-01-23T06:42:34.940753Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.940767Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 199
2023-01-23T06:42:34.941842Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.941860Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 200
2023-01-23T06:42:34.943241Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.943255Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 201
2023-01-23T06:42:34.944432Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.944450Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 202
2023-01-23T06:42:34.945456Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.945470Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 203
2023-01-23T06:42:34.946592Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.946606Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 204
2023-01-23T06:42:34.947674Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.947687Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 205
2023-01-23T06:42:34.948789Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.948802Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 206
2023-01-23T06:42:34.949902Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.949916Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 207
2023-01-23T06:42:34.951004Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.951018Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 208
2023-01-23T06:42:34.952100Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.952113Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 209
2023-01-23T06:42:34.953106Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.953120Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 210
2023-01-23T06:42:34.954244Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.954258Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 211
2023-01-23T06:42:34.955418Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.955432Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 212
2023-01-23T06:42:34.956456Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.956470Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 213
2023-01-23T06:42:34.957506Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.957520Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 214
2023-01-23T06:42:34.958807Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.958824Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 215
2023-01-23T06:42:34.959996Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.960010Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 216
2023-01-23T06:42:34.961043Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.961057Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 217
2023-01-23T06:42:34.962234Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.962248Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 218
2023-01-23T06:42:34.963399Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.963412Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 219
2023-01-23T06:42:34.964500Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.964513Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 220
2023-01-23T06:42:34.965623Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.965636Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 221
2023-01-23T06:42:34.966606Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.966620Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 222
2023-01-23T06:42:34.967570Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.967584Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 223
2023-01-23T06:42:34.968869Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.968882Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 224
2023-01-23T06:42:34.970176Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.970242Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 225
2023-01-23T06:42:34.971309Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.971322Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 226
2023-01-23T06:42:34.972441Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.972454Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 227
2023-01-23T06:42:34.973445Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.973458Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 228
2023-01-23T06:42:34.974646Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.974660Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 229
2023-01-23T06:42:34.975713Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.975727Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 230
2023-01-23T06:42:34.976802Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.976816Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 231
2023-01-23T06:42:34.977932Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.977946Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 232
2023-01-23T06:42:34.978986Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.979000Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 233
2023-01-23T06:42:34.980108Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.980122Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 234
2023-01-23T06:42:34.981198Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.981211Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 235
2023-01-23T06:42:34.982356Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.982371Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 236
2023-01-23T06:42:34.983387Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.983400Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 237
2023-01-23T06:42:34.984543Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.984556Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 238
2023-01-23T06:42:34.985628Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.985642Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 239
2023-01-23T06:42:34.986642Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.986655Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 240
2023-01-23T06:42:34.987658Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.987672Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 241
2023-01-23T06:42:34.988730Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.988743Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 242
2023-01-23T06:42:34.989777Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.989790Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 243
2023-01-23T06:42:34.990887Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.990901Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 244
2023-01-23T06:42:34.991915Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.991929Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 245
2023-01-23T06:42:34.992992Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.993007Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 246
2023-01-23T06:42:34.994229Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.994246Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 247
2023-01-23T06:42:34.995311Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.995325Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 248
2023-01-23T06:42:34.996501Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.996516Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 249
2023-01-23T06:42:34.997588Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.997603Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 250
2023-01-23T06:42:34.998659Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.998674Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 251
2023-01-23T06:42:34.999757Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:34.999771Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 252
2023-01-23T06:42:35.000831Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:35.000845Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 253
2023-01-23T06:42:35.002014Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:35.002028Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 254
2023-01-23T06:42:35.003103Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:35.003117Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 255
2023-01-23T06:42:35.004152Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:35.004166Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 256
2023-01-23T06:42:35.005231Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:35.005246Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 257
2023-01-23T06:42:35.006310Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-23T06:42:35.007436Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-23T06:42:35.007484Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "undefinedOpcodeFirstByte"::Berlin::0
2023-01-23T06:42:35.007495Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/undefinedOpcodeFirstByte.json"
2023-01-23T06:42:35.007506Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T06:42:35.007515Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T06:42:42.597346Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 53335148,
    events_root: None,
}
2023-01-23T06:42:42.597905Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-23T06:42:42.597955Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "undefinedOpcodeFirstByte"::London::0
2023-01-23T06:42:42.597964Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/undefinedOpcodeFirstByte.json"
2023-01-23T06:42:42.597972Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T06:42:42.597978Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T06:42:42.623733Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 52433249,
    events_root: None,
}
2023-01-23T06:42:42.624230Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-23T06:42:42.624278Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "undefinedOpcodeFirstByte"::Merge::0
2023-01-23T06:42:42.624288Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/undefinedOpcodeFirstByte.json"
2023-01-23T06:42:42.624295Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-23T06:42:42.624302Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-23T06:42:42.651880Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 52433249,
    events_root: None,
}
2023-01-23T06:42:42.655179Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stBadOpcode/undefinedOpcodeFirstByte.json"
2023-01-23T06:42:42.655520Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:7.934314734s
```