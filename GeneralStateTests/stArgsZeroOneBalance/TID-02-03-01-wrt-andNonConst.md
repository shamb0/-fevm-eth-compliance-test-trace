> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| OK | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stArgsZeroOneBalance/andNonConst.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/andNonConst.json \
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

> Opcodes

```
0000 PUSH20 0x095e7baea6a6c7c4c2dfeb977efac326af552d87
0015 BALANCE
0016 PUSH20 0x095e7baea6a6c7c4c2dfeb977efac326af552d87
002b BALANCE
002c AND
002d PUSH1 0x00
002f SSTORE
0030 STOP
```

> Execution Trace

```
2023-01-20T14:12:35.076823Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/andNonConst.json", Total Files :: 1
2023-01-20T14:12:35.077273Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/andNonConst.json"
2023-01-20T14:12:35.191288Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [9, 94, 123, 174, 166, 166, 199, 196, 194, 223, 235, 151, 126, 250, 195, 38, 175, 85, 45, 135, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-20T14:12:47.472227Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-20T14:12:47.472419Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T14:12:47.472499Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzacecjf7f47u6czyqywnqsumzmvrtot2a55vtu22glmc44agihdvj5tu
[DEBUG] fetching parameters block: 1
2023-01-20T14:12:47.475417Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-20T14:12:47.475554Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T14:12:47.476715Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-20T14:12:47.476770Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "andNonConst"::Istanbul::0
2023-01-20T14:12:47.476779Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/andNonConst.json"
2023-01-20T14:12:47.476787Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T14:12:47.476794Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T14:12:47.477651Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1648526,
    events_root: None,
}
2023-01-20T14:12:47.477686Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-20T14:12:47.477713Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "andNonConst"::Istanbul::0
2023-01-20T14:12:47.477720Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/andNonConst.json"
2023-01-20T14:12:47.477727Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T14:12:47.477733Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T14:12:47.478338Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1648526,
    events_root: None,
}
2023-01-20T14:12:47.478367Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-20T14:12:47.478396Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "andNonConst"::Berlin::0
2023-01-20T14:12:47.478403Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/andNonConst.json"
2023-01-20T14:12:47.478410Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T14:12:47.478416Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T14:12:47.479020Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1648526,
    events_root: None,
}
2023-01-20T14:12:47.479048Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-20T14:12:47.479076Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "andNonConst"::Berlin::0
2023-01-20T14:12:47.479083Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/andNonConst.json"
2023-01-20T14:12:47.479090Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T14:12:47.479096Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T14:12:47.479732Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1648526,
    events_root: None,
}
2023-01-20T14:12:47.479762Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-20T14:12:47.479790Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "andNonConst"::London::0
2023-01-20T14:12:47.479797Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/andNonConst.json"
2023-01-20T14:12:47.479804Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T14:12:47.479811Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T14:12:47.480426Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1648526,
    events_root: None,
}
2023-01-20T14:12:47.480453Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-20T14:12:47.480482Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "andNonConst"::London::0
2023-01-20T14:12:47.480489Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/andNonConst.json"
2023-01-20T14:12:47.480496Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T14:12:47.480501Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T14:12:47.481104Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1648526,
    events_root: None,
}
2023-01-20T14:12:47.481132Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-20T14:12:47.481161Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "andNonConst"::Merge::0
2023-01-20T14:12:47.481167Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/andNonConst.json"
2023-01-20T14:12:47.481174Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T14:12:47.481180Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T14:12:47.481789Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1648526,
    events_root: None,
}
2023-01-20T14:12:47.481816Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-20T14:12:47.481845Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "andNonConst"::Merge::0
2023-01-20T14:12:47.481852Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/andNonConst.json"
2023-01-20T14:12:47.481859Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T14:12:47.481864Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-20T14:12:47.482462Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1648526,
    events_root: None,
}
2023-01-20T14:12:47.484655Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/andNonConst.json"
2023-01-20T14:12:47.484908Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:12.291229902s
```
