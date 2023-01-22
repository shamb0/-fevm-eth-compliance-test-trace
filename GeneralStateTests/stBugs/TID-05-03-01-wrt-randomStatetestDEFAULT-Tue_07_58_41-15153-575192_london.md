> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stBugs/randomStatetestDEFAULT-Tue_07_58_41-15153-575192_london.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stBugs/randomStatetestDEFAULT-Tue_07_58_41-15153-575192_london.json \
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
		"0x5fde07"
	],
	"gasPrice" : "0x0a",
	"nonce" : "0x1c",
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
0000 PUSH2 0xdead
0003 PUSH1 0x00
0005 PUSH1 0x00
0007 PUSH1 0x00
0009 PUSH1 0x00
000b PUSH1 0x00
000d PUSH2 0xdead
0010 GAS
0011 CALL
0012 PUSH3 0xabcdef
0016 EXTCODEHASH
0017 PUSH1 0x01
0019 SSTORE
```

> Execution Trace

```
2023-01-20T15:06:03.040935Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stBugs/randomStatetestDEFAULT-Tue_07_58_41-15153-575192_london.json", Total Files :: 1
2023-01-20T15:06:03.041381Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stBugs/randomStatetestDEFAULT-Tue_07_58_41-15153-575192_london.json"
2023-01-20T15:06:03.156628Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 222, 173, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-20T15:06:15.048073Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-20T15:06:15.048266Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T15:06:15.048344Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzacednskhdb4sby2jqqez73jl6tjdnvpew2ummzp3qlcjgtbb2f5tlu4
[DEBUG] fetching parameters block: 1
2023-01-20T15:06:15.051379Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-20T15:06:15.051517Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T15:06:15.051560Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([135, 86, 195, 226, 17, 192, 42, 192, 25, 213, 136, 254, 18, 95, 50, 68, 155, 121, 209, 130]) }
[DEBUG] getting cid: bafy2bzaceabmvr4his5duvdynu26lkdmpzqssi7yvdntb6d5nkka6qgxk4hd4
[DEBUG] fetching parameters block: 1
2023-01-20T15:06:15.054636Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [202]
2023-01-20T15:06:15.054781Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T15:06:15.055967Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-20T15:06:15.056022Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "randomStatetestDEFAULT-Tue_07_58_41-15153-575192_london"::Istanbul::0
2023-01-20T15:06:15.056037Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBugs/randomStatetestDEFAULT-Tue_07_58_41-15153-575192_london.json"
2023-01-20T15:06:15.056046Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T15:06:15.056054Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
2023-01-20T15:06:15.058513Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5980136,
    events_root: None,
}
2023-01-20T15:06:15.058556Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-20T15:06:15.058586Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "randomStatetestDEFAULT-Tue_07_58_41-15153-575192_london"::Berlin::0
2023-01-20T15:06:15.058593Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBugs/randomStatetestDEFAULT-Tue_07_58_41-15153-575192_london.json"
2023-01-20T15:06:15.058601Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T15:06:15.058606Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
2023-01-20T15:06:15.059736Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2706925,
    events_root: None,
}
2023-01-20T15:06:15.059769Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-20T15:06:15.059798Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "randomStatetestDEFAULT-Tue_07_58_41-15153-575192_london"::London::0
2023-01-20T15:06:15.059806Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBugs/randomStatetestDEFAULT-Tue_07_58_41-15153-575192_london.json"
2023-01-20T15:06:15.059813Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T15:06:15.059819Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
2023-01-20T15:06:15.060940Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2706925,
    events_root: None,
}
2023-01-20T15:06:15.060974Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-20T15:06:15.061004Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "randomStatetestDEFAULT-Tue_07_58_41-15153-575192_london"::Merge::0
2023-01-20T15:06:15.061011Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBugs/randomStatetestDEFAULT-Tue_07_58_41-15153-575192_london.json"
2023-01-20T15:06:15.061018Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-20T15:06:15.061024Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
2023-01-20T15:06:15.062153Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2706925,
    events_root: None,
}
2023-01-20T15:06:15.064267Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stBugs/randomStatetestDEFAULT-Tue_07_58_41-15153-575192_london.json"
2023-01-20T15:06:15.064612Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:11.905585786s
```
