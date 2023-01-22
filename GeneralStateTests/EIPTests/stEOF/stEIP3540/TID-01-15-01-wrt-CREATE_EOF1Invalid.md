> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

EIP-3541: Contract code starting with the 0xEF byte is disallowed

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json \
	cargo run \
	-- \
	statetest
```

> Execution Trace

```
2023-01-20T10:43:43.179505Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json", Total Files :: 1
2023-01-20T10:43:43.179961Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:43.331089Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.449262Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-20T10:43:55.449450Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T10:43:55.449535Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [185, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzacecsquj7xh4vk2t3fxpfxek3wh4jdtmd7u5en66azvnwf7l4u47cl6
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.452807Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-20T10:43:55.452996Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T10:43:55.454565Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-20T10:43:55.454637Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::0
2023-01-20T10:43:55.454652Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.454664Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-20T10:43:55.454674Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [241, 236, 249, 132, 137, 250, 158, 214, 10, 102, 79, 196, 153, 141, 182, 153, 207, 163, 157, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.459747Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12337163,
    events_root: None,
}
2023-01-20T10:43:55.459841Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-20T10:43:55.459902Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::1
2023-01-20T10:43:55.459915Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.459926Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:43:55.459935Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [48, 199, 204, 13, 24, 18, 59, 68, 92, 38, 54, 255, 144, 105, 239, 40, 192, 220, 50, 181, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.464270Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10954144,
    events_root: None,
}
2023-01-20T10:43:55.464355Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-20T10:43:55.464411Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::2
2023-01-20T10:43:55.464418Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.464426Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:43:55.464432Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [255, 21, 28, 98, 28, 208, 17, 227, 83, 250, 27, 226, 175, 63, 240, 37, 110, 106, 80, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.468134Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11329375,
    events_root: None,
}
2023-01-20T10:43:55.468190Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-20T10:43:55.468228Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::3
2023-01-20T10:43:55.468235Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.468244Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:43:55.468250Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [193, 57, 143, 218, 62, 130, 66, 171, 177, 232, 76, 26, 147, 222, 134, 195, 94, 69, 115, 109, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.472107Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12176390,
    events_root: None,
}
2023-01-20T10:43:55.472171Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-20T10:43:55.472208Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::4
2023-01-20T10:43:55.472216Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.472223Z  INFO evm_eth_compliance::statetest::runner: TX len : 2
2023-01-20T10:43:55.472229Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [154, 50, 77, 163, 110, 182, 144, 38, 253, 105, 17, 166, 109, 248, 185, 1, 87, 69, 133, 174, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([236, 70, 216, 243, 101, 99, 189, 62, 205, 26, 208, 253, 84, 36, 48, 143, 166, 88, 135, 41]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.475891Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10956075,
    events_root: None,
}
2023-01-20T10:43:55.475966Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-20T10:43:55.476014Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::5
2023-01-20T10:43:55.476021Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.476029Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:43:55.476035Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [189, 68, 90, 128, 148, 224, 158, 233, 28, 103, 205, 252, 185, 65, 131, 255, 215, 203, 54, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([155, 99, 140, 31, 46, 96, 27, 93, 44, 60, 131, 66, 80, 136, 87, 209, 224, 27, 216, 212]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.479593Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11454958,
    events_root: None,
}
2023-01-20T10:43:55.479648Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-20T10:43:55.479677Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::6
2023-01-20T10:43:55.479684Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.479691Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:43:55.479697Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [69, 64, 36, 173, 122, 16, 109, 32, 31, 114, 184, 106, 81, 104, 61, 203, 6, 252, 197, 205, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([188, 149, 186, 245, 1, 91, 222, 203, 63, 25, 86, 169, 35, 110, 18, 124, 122, 60, 238, 128]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.483079Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10970059,
    events_root: None,
}
2023-01-20T10:43:55.483136Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-20T10:43:55.483166Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::7
2023-01-20T10:43:55.483173Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.483180Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:43:55.483186Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [194, 131, 118, 103, 84, 0, 194, 247, 86, 42, 206, 139, 162, 196, 196, 211, 161, 85, 182, 80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([20, 3, 204, 71, 166, 252, 88, 221, 29, 77, 14, 224, 191, 132, 61, 100, 47, 53, 166, 175]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.486726Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12196133,
    events_root: None,
}
2023-01-20T10:43:55.486780Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 8
2023-01-20T10:43:55.486809Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::8
2023-01-20T10:43:55.486816Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.486823Z  INFO evm_eth_compliance::statetest::runner: TX len : 3
2023-01-20T10:43:55.486829Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [18, 223, 112, 40, 200, 105, 79, 126, 234, 22, 143, 213, 66, 233, 59, 16, 239, 176, 101, 212, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([177, 189, 137, 170, 161, 168, 98, 8, 218, 14, 105, 2, 242, 92, 44, 234, 2, 122, 233, 63]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.490108Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10428323,
    events_root: None,
}
2023-01-20T10:43:55.490180Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 9
2023-01-20T10:43:55.490220Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::9
2023-01-20T10:43:55.490231Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.490243Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T10:43:55.490253Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [71, 109, 183, 51, 118, 252, 178, 73, 62, 239, 26, 227, 238, 167, 109, 116, 60, 178, 114, 146, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([178, 221, 99, 117, 94, 25, 113, 14, 55, 217, 63, 213, 179, 235, 175, 240, 178, 120, 15, 225]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.493795Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10420735,
    events_root: None,
}
2023-01-20T10:43:55.493849Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 10
2023-01-20T10:43:55.493880Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::10
2023-01-20T10:43:55.493888Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.493895Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T10:43:55.493901Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [240, 140, 34, 50, 177, 145, 236, 253, 142, 147, 12, 62, 113, 220, 195, 187, 176, 6, 190, 46, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([251, 114, 94, 192, 108, 10, 201, 112, 101, 197, 5, 103, 36, 134, 180, 68, 48, 44, 184, 84]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.497335Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10417031,
    events_root: None,
}
2023-01-20T10:43:55.497413Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 11
2023-01-20T10:43:55.497463Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::11
2023-01-20T10:43:55.497471Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.497479Z  INFO evm_eth_compliance::statetest::runner: TX len : 5
2023-01-20T10:43:55.497486Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [138, 63, 117, 129, 127, 14, 183, 64, 104, 21, 202, 39, 175, 242, 213, 209, 150, 89, 199, 187, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([90, 217, 32, 146, 24, 201, 117, 10, 10, 210, 28, 70, 31, 30, 132, 56, 243, 180, 75, 35]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.501109Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11318758,
    events_root: None,
}
2023-01-20T10:43:55.501161Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 12
2023-01-20T10:43:55.501194Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::12
2023-01-20T10:43:55.501202Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.501209Z  INFO evm_eth_compliance::statetest::runner: TX len : 7
2023-01-20T10:43:55.501215Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [211, 219, 59, 193, 71, 175, 72, 205, 181, 99, 156, 64, 77, 103, 103, 42, 134, 209, 231, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([128, 138, 188, 155, 213, 11, 225, 143, 246, 50, 199, 246, 94, 148, 129, 183, 56, 152, 76, 55]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.504587Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11335470,
    events_root: None,
}
2023-01-20T10:43:55.504638Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 13
2023-01-20T10:43:55.504667Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::13
2023-01-20T10:43:55.504674Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.504682Z  INFO evm_eth_compliance::statetest::runner: TX len : 8
2023-01-20T10:43:55.504688Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [108, 151, 22, 178, 162, 25, 203, 145, 112, 53, 178, 149, 101, 179, 112, 55, 0, 167, 132, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([55, 124, 170, 147, 221, 2, 18, 238, 216, 76, 43, 142, 118, 199, 246, 132, 57, 223, 23, 100]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.508003Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10953907,
    events_root: None,
}
2023-01-20T10:43:55.508054Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 14
2023-01-20T10:43:55.508083Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::14
2023-01-20T10:43:55.508090Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.508097Z  INFO evm_eth_compliance::statetest::runner: TX len : 9
2023-01-20T10:43:55.508104Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [0, 29, 164, 205, 123, 1, 234, 222, 135, 106, 32, 99, 195, 1, 252, 9, 141, 13, 239, 130, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([171, 234, 181, 15, 37, 193, 240, 156, 211, 60, 172, 98, 156, 55, 186, 0, 159, 236, 160, 247]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.512220Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11354866,
    events_root: None,
}
2023-01-20T10:43:55.512294Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 15
2023-01-20T10:43:55.512345Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::15
2023-01-20T10:43:55.512353Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.512361Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:43:55.512367Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [252, 231, 139, 199, 40, 27, 198, 147, 120, 182, 176, 148, 247, 77, 168, 113, 241, 155, 127, 112, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([167, 18, 209, 255, 80, 109, 220, 136, 239, 83, 214, 196, 45, 184, 19, 227, 137, 201, 135, 105]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.516047Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12126828,
    events_root: None,
}
2023-01-20T10:43:55.516101Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 16
2023-01-20T10:43:55.516136Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::16
2023-01-20T10:43:55.516143Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.516151Z  INFO evm_eth_compliance::statetest::runner: TX len : 11
2023-01-20T10:43:55.516158Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [72, 185, 211, 57, 208, 65, 246, 7, 143, 196, 136, 209, 206, 191, 228, 202, 250, 27, 247, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([143, 33, 161, 133, 93, 209, 38, 110, 16, 16, 237, 126, 30, 78, 59, 192, 15, 148, 83, 57]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.519617Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11347509,
    events_root: None,
}
2023-01-20T10:43:55.519667Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 17
2023-01-20T10:43:55.519697Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::17
2023-01-20T10:43:55.519704Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.519711Z  INFO evm_eth_compliance::statetest::runner: TX len : 14
2023-01-20T10:43:55.519717Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [197, 25, 232, 203, 119, 199, 211, 31, 169, 13, 46, 15, 7, 137, 252, 166, 215, 144, 109, 158, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([115, 209, 18, 63, 181, 115, 165, 219, 137, 112, 100, 108, 193, 38, 167, 163, 136, 114, 38, 238]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.523711Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11457440,
    events_root: None,
}
2023-01-20T10:43:55.523778Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 18
2023-01-20T10:43:55.523821Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::18
2023-01-20T10:43:55.523829Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.523836Z  INFO evm_eth_compliance::statetest::runner: TX len : 19
2023-01-20T10:43:55.523843Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [10, 72, 228, 4, 224, 226, 94, 133, 163, 13, 92, 130, 0, 113, 32, 237, 175, 0, 247, 95, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([164, 19, 188, 157, 123, 198, 227, 16, 99, 7, 112, 55, 126, 183, 242, 167, 190, 31, 240, 147]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.527215Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10941388,
    events_root: None,
}
2023-01-20T10:43:55.527267Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 19
2023-01-20T10:43:55.527294Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::19
2023-01-20T10:43:55.527301Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.527308Z  INFO evm_eth_compliance::statetest::runner: TX len : 19
2023-01-20T10:43:55.527314Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [176, 124, 54, 155, 119, 106, 36, 52, 202, 249, 19, 38, 137, 157, 110, 107, 133, 189, 212, 57, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([40, 113, 131, 83, 213, 98, 3, 231, 134, 49, 131, 92, 170, 242, 84, 90, 74, 151, 72, 246]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.531038Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12181897,
    events_root: None,
}
2023-01-20T10:43:55.531138Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 20
2023-01-20T10:43:55.531200Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::20
2023-01-20T10:43:55.531213Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.531225Z  INFO evm_eth_compliance::statetest::runner: TX len : 17
2023-01-20T10:43:55.531234Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [133, 164, 140, 0, 197, 241, 214, 247, 23, 83, 56, 63, 33, 180, 39, 206, 106, 33, 161, 117, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([40, 182, 218, 235, 33, 11, 225, 5, 136, 185, 130, 124, 42, 168, 16, 11, 169, 12, 214, 166]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.535066Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11329811,
    events_root: None,
}
2023-01-20T10:43:55.535122Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 21
2023-01-20T10:43:55.535162Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::21
2023-01-20T10:43:55.535170Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.535177Z  INFO evm_eth_compliance::statetest::runner: TX len : 15
2023-01-20T10:43:55.535184Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [123, 120, 201, 197, 76, 136, 128, 0, 73, 84, 218, 141, 148, 169, 105, 49, 128, 86, 148, 124, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([120, 103, 96, 100, 116, 249, 190, 222, 117, 123, 178, 182, 219, 22, 101, 99, 7, 208, 237, 37]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.538571Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10960345,
    events_root: None,
}
2023-01-20T10:43:55.538629Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 22
2023-01-20T10:43:55.538666Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::22
2023-01-20T10:43:55.538674Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.538682Z  INFO evm_eth_compliance::statetest::runner: TX len : 13
2023-01-20T10:43:55.538688Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [228, 67, 94, 17, 187, 192, 120, 136, 99, 185, 82, 166, 200, 195, 30, 60, 155, 89, 70, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([173, 101, 220, 118, 126, 227, 221, 111, 130, 239, 232, 201, 210, 70, 69, 50, 207, 38, 17, 72]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.542244Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10431183,
    events_root: None,
}
2023-01-20T10:43:55.542307Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 23
2023-01-20T10:43:55.542353Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::23
2023-01-20T10:43:55.542360Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.542368Z  INFO evm_eth_compliance::statetest::runner: TX len : 19
2023-01-20T10:43:55.542375Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [165, 217, 138, 175, 43, 127, 195, 217, 211, 200, 95, 45, 165, 37, 199, 223, 211, 181, 225, 27, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([21, 34, 247, 70, 142, 122, 19, 174, 255, 98, 183, 37, 253, 210, 62, 191, 224, 79, 199, 228]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.545814Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11261252,
    events_root: None,
}
2023-01-20T10:43:55.545867Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 24
2023-01-20T10:43:55.545896Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::24
2023-01-20T10:43:55.545903Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.545910Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T10:43:55.545915Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [180, 17, 189, 62, 15, 22, 61, 16, 160, 97, 102, 150, 154, 92, 5, 123, 99, 111, 96, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([121, 200, 128, 32, 100, 47, 163, 168, 222, 154, 90, 196, 49, 165, 55, 116, 4, 152, 177, 42]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.549614Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11803807,
    events_root: None,
}
2023-01-20T10:43:55.549670Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 25
2023-01-20T10:43:55.549701Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::25
2023-01-20T10:43:55.549707Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.549714Z  INFO evm_eth_compliance::statetest::runner: TX len : 27
2023-01-20T10:43:55.549720Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [248, 211, 153, 208, 156, 222, 218, 19, 203, 57, 87, 202, 41, 199, 179, 235, 11, 22, 167, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([39, 202, 0, 61, 220, 84, 98, 79, 206, 62, 176, 253, 44, 186, 245, 199, 23, 163, 253, 50]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.552924Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10436481,
    events_root: None,
}
2023-01-20T10:43:55.552977Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 26
2023-01-20T10:43:55.553007Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::26
2023-01-20T10:43:55.553014Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.553022Z  INFO evm_eth_compliance::statetest::runner: TX len : 19
2023-01-20T10:43:55.553028Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [120, 198, 25, 54, 120, 6, 173, 45, 83, 40, 187, 135, 19, 212, 172, 98, 144, 65, 111, 117, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([192, 88, 99, 161, 23, 254, 175, 39, 213, 169, 153, 253, 197, 254, 95, 117, 145, 246, 7, 95]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.556392Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11326810,
    events_root: None,
}
2023-01-20T10:43:55.556442Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 27
2023-01-20T10:43:55.556471Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::27
2023-01-20T10:43:55.556478Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.556485Z  INFO evm_eth_compliance::statetest::runner: TX len : 19
2023-01-20T10:43:55.556491Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [42, 35, 20, 104, 47, 224, 227, 72, 70, 126, 85, 169, 135, 69, 253, 85, 80, 193, 253, 70, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([96, 33, 187, 115, 222, 53, 224, 244, 47, 32, 70, 11, 226, 18, 129, 166, 126, 239, 230, 44]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.559935Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11465488,
    events_root: None,
}
2023-01-20T10:43:55.559991Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 28
2023-01-20T10:43:55.560021Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::28
2023-01-20T10:43:55.560028Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.560035Z  INFO evm_eth_compliance::statetest::runner: TX len : 13
2023-01-20T10:43:55.560042Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [0, 221, 86, 37, 37, 249, 57, 46, 175, 151, 244, 145, 10, 82, 179, 240, 26, 220, 90, 27, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([221, 202, 25, 212, 34, 2, 50, 123, 41, 75, 186, 155, 123, 166, 127, 9, 228, 237, 116, 209]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.563829Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11330835,
    events_root: None,
}
2023-01-20T10:43:55.563899Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 29
2023-01-20T10:43:55.563949Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::29
2023-01-20T10:43:55.563957Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.563964Z  INFO evm_eth_compliance::statetest::runner: TX len : 21
2023-01-20T10:43:55.563970Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [202, 10, 213, 110, 213, 236, 3, 149, 190, 14, 175, 221, 16, 58, 247, 171, 121, 44, 189, 163, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([96, 157, 121, 180, 71, 136, 28, 182, 195, 187, 216, 146, 44, 166, 42, 126, 234, 16, 198, 148]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.567597Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11342816,
    events_root: None,
}
2023-01-20T10:43:55.567654Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 30
2023-01-20T10:43:55.567690Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::30
2023-01-20T10:43:55.567698Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.567706Z  INFO evm_eth_compliance::statetest::runner: TX len : 22
2023-01-20T10:43:55.567712Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [198, 160, 133, 219, 7, 149, 77, 105, 88, 246, 129, 212, 186, 113, 39, 103, 241, 76, 195, 119, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([125, 213, 185, 126, 102, 183, 165, 62, 81, 45, 4, 229, 242, 150, 184, 46, 206, 140, 135, 167]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.571060Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10428267,
    events_root: None,
}
2023-01-20T10:43:55.571119Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 31
2023-01-20T10:43:55.571156Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::31
2023-01-20T10:43:55.571164Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.571171Z  INFO evm_eth_compliance::statetest::runner: TX len : 22
2023-01-20T10:43:55.571177Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [55, 216, 190, 61, 33, 255, 92, 145, 40, 143, 154, 251, 143, 9, 132, 32, 148, 92, 237, 186, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([57, 47, 201, 253, 31, 210, 216, 45, 82, 53, 15, 10, 140, 189, 182, 38, 139, 193, 227, 148]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.575186Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11804732,
    events_root: None,
}
2023-01-20T10:43:55.575267Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 32
2023-01-20T10:43:55.575320Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::32
2023-01-20T10:43:55.575328Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.575335Z  INFO evm_eth_compliance::statetest::runner: TX len : 22
2023-01-20T10:43:55.575341Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [230, 85, 252, 85, 68, 43, 217, 22, 211, 98, 13, 215, 29, 128, 185, 167, 83, 212, 44, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([10, 128, 19, 154, 164, 202, 88, 213, 185, 231, 230, 233, 169, 125, 32, 175, 46, 247, 104, 205]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.578701Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10440175,
    events_root: None,
}
2023-01-20T10:43:55.578750Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 33
2023-01-20T10:43:55.578781Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::33
2023-01-20T10:43:55.578788Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.578795Z  INFO evm_eth_compliance::statetest::runner: TX len : 16
2023-01-20T10:43:55.578800Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [190, 64, 189, 65, 63, 223, 140, 82, 182, 233, 228, 224, 166, 92, 228, 243, 177, 123, 205, 229, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([234, 139, 137, 133, 156, 6, 41, 217, 87, 171, 216, 141, 23, 64, 208, 12, 0, 6, 118, 73]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.582432Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11332680,
    events_root: None,
}
2023-01-20T10:43:55.582496Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 34
2023-01-20T10:43:55.582532Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::34
2023-01-20T10:43:55.582539Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.582546Z  INFO evm_eth_compliance::statetest::runner: TX len : 17
2023-01-20T10:43:55.582552Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [240, 177, 221, 38, 94, 155, 14, 5, 249, 157, 200, 67, 210, 111, 184, 21, 72, 6, 233, 172, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([74, 138, 107, 177, 65, 173, 106, 127, 111, 235, 64, 25, 56, 77, 152, 139, 121, 241, 216, 113]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.585962Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11300555,
    events_root: None,
}
2023-01-20T10:43:55.586013Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 35
2023-01-20T10:43:55.586043Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::35
2023-01-20T10:43:55.586050Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.586058Z  INFO evm_eth_compliance::statetest::runner: TX len : 12
2023-01-20T10:43:55.586064Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [235, 8, 64, 90, 35, 97, 91, 67, 92, 74, 160, 65, 74, 189, 53, 95, 163, 242, 165, 214, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([126, 248, 213, 18, 73, 109, 79, 84, 218, 211, 209, 213, 172, 193, 146, 154, 144, 35, 152, 99]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.589514Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11350608,
    events_root: None,
}
2023-01-20T10:43:55.589572Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 36
2023-01-20T10:43:55.589604Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::36
2023-01-20T10:43:55.589612Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.589619Z  INFO evm_eth_compliance::statetest::runner: TX len : 13
2023-01-20T10:43:55.589626Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [29, 221, 244, 204, 171, 14, 120, 220, 133, 231, 119, 243, 178, 154, 66, 249, 252, 226, 236, 28, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([167, 245, 235, 76, 86, 206, 109, 57, 189, 19, 0, 230, 242, 87, 18, 38, 208, 32, 55, 56]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.593004Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10941730,
    events_root: None,
}
2023-01-20T10:43:55.593056Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 37
2023-01-20T10:43:55.593087Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::37
2023-01-20T10:43:55.593094Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.593101Z  INFO evm_eth_compliance::statetest::runner: TX len : 14
2023-01-20T10:43:55.593107Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [41, 46, 224, 221, 195, 116, 211, 54, 75, 206, 138, 150, 97, 173, 205, 103, 144, 98, 100, 85, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([138, 192, 102, 104, 212, 54, 151, 48, 197, 195, 196, 55, 46, 91, 125, 35, 54, 100, 85, 118]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.596393Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10942950,
    events_root: None,
}
2023-01-20T10:43:55.596447Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 38
2023-01-20T10:43:55.596476Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::38
2023-01-20T10:43:55.596483Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.596490Z  INFO evm_eth_compliance::statetest::runner: TX len : 21
2023-01-20T10:43:55.596496Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [225, 214, 27, 56, 52, 251, 98, 28, 161, 50, 25, 247, 41, 205, 36, 31, 121, 23, 115, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([144, 116, 102, 151, 109, 193, 228, 195, 140, 185, 216, 122, 95, 12, 114, 35, 109, 70, 64, 123]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.600443Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11329731,
    events_root: None,
}
2023-01-20T10:43:55.600524Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 39
2023-01-20T10:43:55.600576Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::39
2023-01-20T10:43:55.600584Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.600591Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T10:43:55.600598Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [10, 209, 97, 123, 195, 62, 165, 236, 110, 251, 213, 90, 230, 111, 226, 213, 196, 84, 237, 152, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([75, 225, 44, 86, 78, 215, 16, 71, 27, 117, 144, 173, 253, 80, 20, 246, 7, 228, 15, 51]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.604050Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10948368,
    events_root: None,
}
2023-01-20T10:43:55.604101Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 40
2023-01-20T10:43:55.604130Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::40
2023-01-20T10:43:55.604137Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.604144Z  INFO evm_eth_compliance::statetest::runner: TX len : 23
2023-01-20T10:43:55.604150Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [239, 140, 20, 252, 95, 162, 39, 0, 11, 179, 224, 109, 118, 145, 73, 58, 82, 26, 199, 153, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([32, 103, 245, 189, 168, 73, 149, 238, 158, 100, 244, 162, 2, 157, 240, 169, 24, 108, 156, 146]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.607556Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11245116,
    events_root: None,
}
2023-01-20T10:43:55.607633Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 41
2023-01-20T10:43:55.607673Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::41
2023-01-20T10:43:55.607681Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.607688Z  INFO evm_eth_compliance::statetest::runner: TX len : 25
2023-01-20T10:43:55.607695Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [134, 95, 90, 131, 43, 165, 157, 140, 197, 179, 238, 65, 145, 160, 218, 149, 39, 212, 138, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([85, 143, 18, 101, 101, 201, 146, 95, 146, 124, 254, 78, 228, 215, 122, 164, 58, 49, 178, 79]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.611377Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10962334,
    events_root: None,
}
2023-01-20T10:43:55.611440Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 42
2023-01-20T10:43:55.611483Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::42
2023-01-20T10:43:55.611492Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.611499Z  INFO evm_eth_compliance::statetest::runner: TX len : 27
2023-01-20T10:43:55.611505Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [163, 139, 161, 12, 69, 31, 224, 64, 174, 44, 205, 29, 149, 9, 56, 188, 192, 116, 86, 43, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 1, 137, 98, 70, 212, 67, 19, 201, 255, 154, 67, 250, 120, 4, 209, 79, 104, 144, 63]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.615018Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11331907,
    events_root: None,
}
2023-01-20T10:43:55.615074Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 43
2023-01-20T10:43:55.615111Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::43
2023-01-20T10:43:55.615118Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.615125Z  INFO evm_eth_compliance::statetest::runner: TX len : 34
2023-01-20T10:43:55.615131Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [179, 171, 220, 108, 222, 228, 146, 253, 166, 75, 22, 154, 128, 128, 184, 118, 227, 249, 71, 34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([224, 185, 252, 233, 220, 182, 210, 59, 215, 224, 114, 129, 224, 209, 243, 213, 50, 205, 235, 229]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.618477Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10451271,
    events_root: None,
}
2023-01-20T10:43:55.618538Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 44
2023-01-20T10:43:55.618580Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::44
2023-01-20T10:43:55.618588Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.618595Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:43:55.618601Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [160, 223, 235, 157, 225, 212, 16, 213, 231, 23, 161, 170, 208, 174, 101, 110, 93, 172, 244, 212, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([202, 216, 7, 119, 106, 153, 146, 153, 17, 117, 69, 127, 5, 244, 55, 40, 94, 200, 169, 244]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.622139Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11786469,
    events_root: None,
}
2023-01-20T10:43:55.622202Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 45
2023-01-20T10:43:55.622241Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::45
2023-01-20T10:43:55.622248Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.622255Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:43:55.622261Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [240, 81, 81, 153, 210, 10, 164, 222, 163, 110, 255, 4, 87, 16, 211, 196, 114, 201, 109, 250, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([66, 164, 235, 226, 198, 211, 185, 232, 137, 80, 14, 181, 142, 113, 122, 170, 52, 30, 146, 127]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.625824Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10427215,
    events_root: None,
}
2023-01-20T10:43:55.625917Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 46
2023-01-20T10:43:55.625977Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::46
2023-01-20T10:43:55.625999Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.626017Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:43:55.626032Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [211, 171, 242, 16, 226, 254, 141, 115, 212, 27, 50, 1, 178, 109, 63, 17, 112, 28, 160, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([59, 53, 249, 29, 97, 100, 74, 37, 144, 142, 18, 90, 172, 2, 157, 156, 29, 149, 16, 132]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.630625Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11796728,
    events_root: None,
}
2023-01-20T10:43:55.630728Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 47
2023-01-20T10:43:55.630795Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::47
2023-01-20T10:43:55.630817Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.630836Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T10:43:55.630852Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [241, 232, 246, 47, 1, 228, 158, 31, 132, 177, 36, 196, 65, 12, 72, 251, 29, 142, 209, 124, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([181, 8, 27, 168, 223, 145, 221, 58, 213, 216, 232, 244, 223, 5, 154, 0, 190, 59, 128, 47]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.635361Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12121023,
    events_root: None,
}
2023-01-20T10:43:55.635444Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 48
2023-01-20T10:43:55.635494Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::48
2023-01-20T10:43:55.635502Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.635509Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T10:43:55.635515Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [91, 240, 24, 58, 235, 222, 219, 248, 108, 122, 127, 37, 61, 233, 98, 192, 187, 81, 164, 77, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([234, 116, 183, 211, 19, 73, 71, 125, 114, 164, 151, 221, 52, 114, 218, 152, 238, 51, 210, 142]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.639297Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11336448,
    events_root: None,
}
2023-01-20T10:43:55.639363Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 49
2023-01-20T10:43:55.639407Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::49
2023-01-20T10:43:55.639415Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.639422Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T10:43:55.639428Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [188, 110, 210, 100, 178, 70, 135, 238, 210, 198, 91, 201, 195, 222, 131, 89, 105, 173, 123, 70, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([3, 57, 19, 218, 51, 98, 88, 97, 53, 102, 56, 142, 234, 63, 251, 161, 22, 162, 140, 2]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.643350Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11326015,
    events_root: None,
}
2023-01-20T10:43:55.643432Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 50
2023-01-20T10:43:55.643487Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::50
2023-01-20T10:43:55.643496Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.643506Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T10:43:55.643514Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [2, 17, 229, 138, 25, 244, 9, 215, 178, 127, 95, 247, 129, 212, 252, 153, 189, 243, 215, 94, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([63, 161, 187, 197, 65, 220, 217, 68, 174, 137, 53, 67, 149, 191, 178, 97, 158, 51, 14, 103]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.647171Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10950129,
    events_root: None,
}
2023-01-20T10:43:55.647223Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 51
2023-01-20T10:43:55.647255Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::51
2023-01-20T10:43:55.647263Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.647270Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T10:43:55.647278Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [155, 148, 93, 84, 95, 159, 235, 166, 1, 174, 16, 98, 114, 97, 79, 235, 99, 162, 113, 46, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([218, 202, 18, 62, 227, 225, 1, 202, 186, 24, 13, 42, 91, 180, 75, 60, 236, 17, 26, 179]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.650959Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12146188,
    events_root: None,
}
2023-01-20T10:43:55.651022Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 52
2023-01-20T10:43:55.651064Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::52
2023-01-20T10:43:55.651073Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.651082Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T10:43:55.651090Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [27, 158, 209, 135, 42, 221, 25, 115, 61, 211, 127, 20, 233, 81, 103, 211, 174, 80, 40, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([42, 8, 0, 137, 245, 202, 239, 57, 123, 81, 148, 98, 201, 144, 167, 86, 38, 89, 1, 145]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.654576Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11326021,
    events_root: None,
}
2023-01-20T10:43:55.654646Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 53
2023-01-20T10:43:55.654692Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::53
2023-01-20T10:43:55.654705Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.654716Z  INFO evm_eth_compliance::statetest::runner: TX len : 24
2023-01-20T10:43:55.654726Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [59, 125, 81, 81, 113, 5, 85, 53, 188, 66, 109, 142, 8, 82, 255, 193, 70, 151, 140, 199, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([104, 62, 254, 77, 166, 98, 129, 212, 171, 54, 46, 64, 123, 176, 69, 61, 126, 37, 183, 206]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.658753Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11326383,
    events_root: None,
}
2023-01-20T10:43:55.658843Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 54
2023-01-20T10:43:55.658906Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::54
2023-01-20T10:43:55.658919Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.658930Z  INFO evm_eth_compliance::statetest::runner: TX len : 24
2023-01-20T10:43:55.658939Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [33, 106, 153, 15, 86, 200, 64, 220, 95, 0, 166, 131, 33, 93, 246, 212, 165, 157, 113, 206, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([120, 60, 68, 193, 57, 146, 249, 107, 202, 249, 8, 241, 235, 157, 91, 127, 14, 110, 57, 206]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.662490Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10946130,
    events_root: None,
}
2023-01-20T10:43:55.662545Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 55
2023-01-20T10:43:55.662585Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::55
2023-01-20T10:43:55.662593Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.662600Z  INFO evm_eth_compliance::statetest::runner: TX len : 24
2023-01-20T10:43:55.662606Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [219, 26, 157, 163, 1, 187, 97, 139, 199, 142, 146, 250, 239, 169, 186, 211, 199, 140, 202, 36, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([147, 215, 35, 79, 72, 183, 254, 242, 194, 29, 172, 136, 14, 237, 250, 252, 242, 51, 127, 97]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.665839Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10441674,
    events_root: None,
}
2023-01-20T10:43:55.665885Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 56
2023-01-20T10:43:55.665916Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::56
2023-01-20T10:43:55.665925Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.665932Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:43:55.665939Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [181, 98, 0, 123, 86, 27, 195, 129, 115, 190, 231, 98, 96, 48, 50, 88, 241, 73, 6, 199, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([242, 200, 122, 171, 63, 235, 198, 140, 32, 232, 76, 42, 197, 165, 51, 1, 171, 177, 228, 41]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.669305Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10964837,
    events_root: None,
}
2023-01-20T10:43:55.669354Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 57
2023-01-20T10:43:55.669386Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::57
2023-01-20T10:43:55.669394Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.669401Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.669407Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [120, 113, 18, 154, 236, 212, 91, 56, 147, 128, 202, 241, 166, 57, 187, 230, 175, 40, 34, 228, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([62, 147, 196, 228, 19, 53, 26, 163, 227, 161, 161, 215, 158, 164, 116, 190, 53, 196, 226, 86]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.672943Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11267954,
    events_root: None,
}
2023-01-20T10:43:55.673015Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 58
2023-01-20T10:43:55.673057Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::58
2023-01-20T10:43:55.673068Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.673079Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.673087Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [87, 219, 218, 89, 201, 122, 2, 51, 106, 8, 107, 92, 121, 99, 157, 172, 168, 144, 98, 103, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([245, 247, 167, 109, 171, 19, 147, 219, 109, 152, 254, 206, 145, 95, 196, 82, 59, 231, 146, 108]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.677101Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11252437,
    events_root: None,
}
2023-01-20T10:43:55.677168Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 59
2023-01-20T10:43:55.677218Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::59
2023-01-20T10:43:55.677226Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.677233Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.677239Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [248, 245, 112, 83, 15, 146, 239, 241, 163, 235, 125, 247, 123, 137, 103, 196, 125, 137, 156, 121, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([7, 158, 84, 58, 120, 147, 60, 147, 138, 143, 25, 166, 137, 140, 78, 245, 163, 245, 15, 240]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.680651Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11350281,
    events_root: None,
}
2023-01-20T10:43:55.680697Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 60
2023-01-20T10:43:55.680726Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::60
2023-01-20T10:43:55.680733Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.680740Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.680746Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [65, 75, 234, 34, 24, 132, 175, 106, 150, 135, 110, 45, 172, 39, 153, 7, 156, 83, 154, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([101, 116, 187, 125, 159, 134, 103, 253, 71, 28, 161, 28, 224, 159, 118, 18, 173, 248, 106, 178]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.684008Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10433920,
    events_root: None,
}
2023-01-20T10:43:55.684055Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 61
2023-01-20T10:43:55.684087Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::61
2023-01-20T10:43:55.684094Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.684101Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.684107Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [143, 62, 73, 219, 136, 161, 160, 77, 80, 224, 174, 15, 148, 154, 122, 237, 173, 77, 107, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([155, 95, 242, 9, 90, 122, 82, 95, 203, 251, 122, 183, 134, 20, 92, 45, 133, 143, 190, 79]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.687594Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12097651,
    events_root: None,
}
2023-01-20T10:43:55.687642Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 62
2023-01-20T10:43:55.687671Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::62
2023-01-20T10:43:55.687678Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.687685Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.687691Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [217, 162, 168, 113, 141, 103, 236, 53, 22, 157, 134, 54, 161, 29, 115, 9, 239, 18, 18, 212, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([54, 233, 149, 112, 243, 205, 226, 29, 96, 223, 210, 91, 9, 119, 78, 94, 236, 137, 95, 47]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.691179Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11479401,
    events_root: None,
}
2023-01-20T10:43:55.691237Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 63
2023-01-20T10:43:55.691277Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::63
2023-01-20T10:43:55.691285Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.691292Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.691298Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [235, 27, 83, 177, 253, 126, 10, 101, 31, 105, 183, 106, 176, 161, 8, 249, 93, 168, 236, 173, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([238, 253, 241, 172, 208, 208, 47, 210, 127, 104, 145, 191, 55, 169, 92, 159, 79, 33, 124, 81]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.694968Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10971487,
    events_root: None,
}
2023-01-20T10:43:55.695025Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 64
2023-01-20T10:43:55.695068Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::64
2023-01-20T10:43:55.695076Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.695083Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.695089Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [160, 82, 171, 68, 110, 150, 40, 186, 201, 138, 187, 45, 0, 93, 122, 185, 96, 254, 72, 122, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([172, 213, 217, 59, 199, 164, 245, 110, 126, 219, 117, 176, 255, 50, 179, 203, 237, 224, 86, 53]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.698315Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10468549,
    events_root: None,
}
2023-01-20T10:43:55.698363Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 65
2023-01-20T10:43:55.698394Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::65
2023-01-20T10:43:55.698402Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.698410Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.698416Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [44, 193, 182, 184, 205, 18, 206, 51, 241, 57, 219, 197, 43, 137, 62, 252, 112, 233, 191, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([233, 196, 35, 214, 167, 136, 168, 70, 9, 81, 41, 154, 152, 150, 120, 187, 161, 211, 14, 66]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.701788Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11398652,
    events_root: None,
}
2023-01-20T10:43:55.701839Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 66
2023-01-20T10:43:55.701870Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::66
2023-01-20T10:43:55.701877Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.701884Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.701890Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [173, 181, 32, 255, 239, 62, 57, 248, 214, 241, 20, 142, 84, 4, 1, 215, 162, 213, 105, 68, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([160, 22, 178, 28, 123, 24, 4, 205, 147, 64, 111, 144, 122, 198, 167, 128, 46, 191, 140, 52]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.705408Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11331221,
    events_root: None,
}
2023-01-20T10:43:55.705475Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 67
2023-01-20T10:43:55.705516Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::67
2023-01-20T10:43:55.705528Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.705539Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.705548Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [146, 188, 81, 9, 134, 189, 4, 18, 151, 13, 74, 206, 93, 13, 253, 124, 111, 180, 249, 202, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([6, 101, 24, 32, 72, 254, 76, 158, 23, 230, 180, 249, 6, 77, 81, 181, 195, 46, 12, 239]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.709423Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11265351,
    events_root: None,
}
2023-01-20T10:43:55.709485Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 68
2023-01-20T10:43:55.709533Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::68
2023-01-20T10:43:55.709540Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.709548Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.709554Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [82, 18, 92, 247, 176, 46, 226, 247, 126, 49, 248, 20, 171, 67, 128, 101, 216, 197, 250, 134, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([210, 200, 59, 201, 171, 234, 215, 190, 204, 216, 178, 133, 65, 168, 237, 79, 59, 110, 253, 88]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.713071Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12200233,
    events_root: None,
}
2023-01-20T10:43:55.713119Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 69
2023-01-20T10:43:55.713146Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::69
2023-01-20T10:43:55.713153Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.713160Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.713166Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [147, 32, 43, 126, 63, 50, 202, 244, 16, 188, 1, 62, 198, 182, 207, 43, 48, 40, 124, 235, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([152, 179, 153, 86, 207, 123, 119, 235, 95, 203, 67, 81, 180, 228, 252, 230, 238, 226, 128, 101]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.716693Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12092254,
    events_root: None,
}
2023-01-20T10:43:55.716743Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 70
2023-01-20T10:43:55.716775Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::70
2023-01-20T10:43:55.716783Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.716790Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.716796Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [142, 36, 48, 174, 241, 21, 41, 192, 20, 1, 27, 131, 180, 117, 188, 213, 6, 131, 161, 188, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([138, 38, 243, 153, 218, 225, 55, 155, 27, 229, 106, 36, 160, 218, 25, 26, 79, 118, 84, 124]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.719973Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10447683,
    events_root: None,
}
2023-01-20T10:43:55.720019Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 71
2023-01-20T10:43:55.720047Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::71
2023-01-20T10:43:55.720053Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.720060Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.720066Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [119, 223, 217, 169, 136, 177, 127, 90, 30, 90, 69, 142, 91, 153, 119, 119, 139, 106, 150, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([36, 34, 142, 247, 128, 110, 247, 94, 198, 71, 114, 180, 208, 238, 227, 169, 93, 167, 249, 138]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.724039Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10960421,
    events_root: None,
}
2023-01-20T10:43:55.724114Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 72
2023-01-20T10:43:55.724163Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::72
2023-01-20T10:43:55.724171Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.724179Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.724185Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [231, 153, 146, 158, 58, 188, 185, 234, 18, 111, 240, 141, 114, 207, 45, 125, 192, 66, 8, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([223, 135, 238, 67, 51, 204, 134, 29, 70, 229, 97, 185, 114, 169, 34, 58, 250, 236, 1, 80]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.727656Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11268616,
    events_root: None,
}
2023-01-20T10:43:55.727703Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 73
2023-01-20T10:43:55.727731Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::73
2023-01-20T10:43:55.727738Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.727745Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.727750Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [196, 144, 95, 101, 255, 45, 252, 31, 50, 41, 80, 83, 91, 211, 136, 98, 30, 21, 156, 114, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([171, 123, 201, 143, 214, 163, 34, 102, 246, 229, 97, 228, 11, 37, 109, 19, 5, 221, 226, 152]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.731251Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12138317,
    events_root: None,
}
2023-01-20T10:43:55.731301Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 74
2023-01-20T10:43:55.731331Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::74
2023-01-20T10:43:55.731338Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.731345Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.731351Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [70, 96, 144, 187, 111, 245, 57, 191, 184, 145, 4, 49, 201, 219, 80, 31, 79, 7, 254, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([150, 121, 248, 15, 109, 83, 111, 178, 241, 144, 29, 41, 236, 59, 127, 169, 171, 108, 240, 235]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.734548Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10437687,
    events_root: None,
}
2023-01-20T10:43:55.734597Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 75
2023-01-20T10:43:55.734626Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::75
2023-01-20T10:43:55.734633Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.734642Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.734648Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [20, 74, 10, 179, 138, 141, 32, 213, 59, 235, 191, 114, 154, 4, 64, 62, 142, 183, 97, 98, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([216, 255, 189, 112, 116, 100, 130, 35, 19, 172, 20, 178, 52, 203, 193, 91, 93, 144, 244, 170]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.738258Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11260475,
    events_root: None,
}
2023-01-20T10:43:55.738338Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 76
2023-01-20T10:43:55.738373Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::76
2023-01-20T10:43:55.738380Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.738388Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.738394Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [77, 17, 137, 47, 178, 108, 94, 20, 250, 67, 105, 139, 137, 242, 36, 229, 11, 254, 197, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([166, 79, 125, 93, 55, 208, 234, 109, 248, 252, 50, 181, 233, 25, 133, 95, 16, 4, 250, 212]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.742303Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12187383,
    events_root: None,
}
2023-01-20T10:43:55.742378Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 77
2023-01-20T10:43:55.742424Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::77
2023-01-20T10:43:55.742432Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.742439Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.742445Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [83, 20, 103, 239, 12, 33, 173, 215, 229, 98, 236, 145, 216, 182, 87, 81, 107, 143, 17, 81, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([2, 173, 127, 180, 225, 10, 235, 13, 93, 152, 13, 38, 145, 37, 45, 245, 145, 35, 49, 187]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.745812Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10971557,
    events_root: None,
}
2023-01-20T10:43:55.745864Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 78
2023-01-20T10:43:55.745892Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::78
2023-01-20T10:43:55.745899Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.745906Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.745912Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [100, 27, 189, 19, 87, 84, 162, 255, 208, 204, 198, 173, 229, 33, 182, 103, 227, 19, 129, 213, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([26, 94, 21, 132, 72, 150, 253, 219, 60, 75, 126, 210, 38, 54, 187, 181, 69, 150, 199, 238]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.749261Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11254775,
    events_root: None,
}
2023-01-20T10:43:55.749313Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 79
2023-01-20T10:43:55.749343Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::79
2023-01-20T10:43:55.749350Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.749357Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.749363Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [191, 109, 22, 254, 159, 172, 186, 22, 136, 80, 109, 82, 159, 235, 130, 63, 181, 221, 33, 244, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([175, 251, 80, 249, 105, 130, 119, 145, 133, 148, 208, 51, 71, 178, 169, 202, 39, 153, 152, 110]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.752770Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11473637,
    events_root: None,
}
2023-01-20T10:43:55.752821Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 80
2023-01-20T10:43:55.752850Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::80
2023-01-20T10:43:55.752857Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.752864Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.752870Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [52, 10, 26, 61, 234, 174, 190, 183, 250, 91, 162, 139, 103, 29, 231, 233, 234, 32, 102, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([183, 147, 254, 58, 179, 36, 249, 194, 136, 77, 164, 228, 236, 185, 91, 29, 246, 206, 249, 29]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.756581Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11337549,
    events_root: None,
}
2023-01-20T10:43:55.756635Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 81
2023-01-20T10:43:55.756666Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::81
2023-01-20T10:43:55.756673Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.756681Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.756687Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [219, 220, 219, 136, 196, 115, 191, 89, 45, 216, 38, 105, 17, 219, 105, 193, 172, 165, 79, 245, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([120, 168, 127, 221, 78, 78, 205, 221, 40, 101, 104, 53, 169, 89, 117, 62, 45, 246, 126, 10]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.760216Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10432734,
    events_root: None,
}
2023-01-20T10:43:55.760288Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 82
2023-01-20T10:43:55.760334Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::82
2023-01-20T10:43:55.760342Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.760350Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.760356Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [103, 14, 81, 199, 129, 28, 252, 84, 41, 74, 229, 147, 31, 252, 25, 251, 78, 129, 119, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 95, 145, 17, 53, 205, 188, 252, 222, 81, 19, 14, 225, 44, 173, 102, 10, 139, 61, 204]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.763858Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11317967,
    events_root: None,
}
2023-01-20T10:43:55.763910Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 83
2023-01-20T10:43:55.763941Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::83
2023-01-20T10:43:55.763948Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.763955Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.763962Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [82, 225, 157, 6, 114, 118, 167, 255, 107, 125, 179, 191, 171, 162, 161, 132, 114, 141, 209, 214, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([5, 88, 210, 18, 26, 52, 248, 28, 151, 64, 33, 131, 197, 186, 68, 48, 182, 55, 124, 252]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.767353Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11282079,
    events_root: None,
}
2023-01-20T10:43:55.767406Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 84
2023-01-20T10:43:55.767439Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::84
2023-01-20T10:43:55.767446Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.767453Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.767459Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [140, 70, 232, 96, 227, 103, 248, 57, 79, 90, 49, 166, 197, 206, 144, 107, 153, 223, 147, 66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([15, 247, 128, 210, 25, 115, 102, 75, 127, 51, 97, 15, 6, 109, 66, 23, 2, 119, 106, 150]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.770781Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11352111,
    events_root: None,
}
2023-01-20T10:43:55.770831Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 85
2023-01-20T10:43:55.770860Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::85
2023-01-20T10:43:55.770867Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.770874Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.770880Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [12, 155, 77, 86, 66, 98, 66, 141, 71, 136, 33, 16, 140, 143, 40, 164, 197, 143, 213, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([199, 252, 73, 148, 203, 140, 110, 81, 23, 89, 7, 17, 67, 216, 186, 246, 144, 79, 37, 28]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.774742Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10448800,
    events_root: None,
}
2023-01-20T10:43:55.774817Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 86
2023-01-20T10:43:55.774866Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::86
2023-01-20T10:43:55.774873Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.774880Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.774887Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [177, 232, 93, 251, 188, 111, 53, 185, 36, 206, 14, 205, 7, 49, 43, 63, 58, 183, 181, 54, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([118, 83, 126, 208, 253, 224, 235, 219, 150, 244, 223, 154, 156, 51, 158, 143, 75, 69, 63, 136]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.778327Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11363218,
    events_root: None,
}
2023-01-20T10:43:55.778379Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 87
2023-01-20T10:43:55.778407Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::87
2023-01-20T10:43:55.778414Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.778421Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.778428Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [112, 71, 3, 252, 236, 172, 246, 135, 189, 39, 144, 243, 197, 103, 149, 200, 117, 209, 31, 114, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([166, 190, 176, 88, 26, 69, 172, 111, 50, 159, 85, 218, 194, 71, 246, 209, 144, 181, 175, 145]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.781971Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12258123,
    events_root: None,
}
2023-01-20T10:43:55.782026Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 88
2023-01-20T10:43:55.782056Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::88
2023-01-20T10:43:55.782063Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.782070Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.782076Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [168, 129, 98, 9, 89, 94, 202, 162, 122, 19, 171, 235, 85, 180, 143, 231, 94, 81, 232, 22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([36, 157, 234, 94, 37, 166, 2, 133, 61, 174, 211, 48, 33, 142, 84, 86, 31, 155, 191, 251]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.785375Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11347261,
    events_root: None,
}
2023-01-20T10:43:55.785425Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 89
2023-01-20T10:43:55.785454Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::89
2023-01-20T10:43:55.785461Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.785468Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.785474Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [117, 232, 53, 11, 217, 220, 180, 1, 94, 170, 28, 189, 140, 43, 188, 209, 236, 138, 249, 151, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([168, 221, 180, 246, 133, 219, 169, 147, 169, 53, 222, 23, 131, 225, 185, 196, 200, 150, 125, 157]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.788869Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10472363,
    events_root: None,
}
2023-01-20T10:43:55.788937Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 90
2023-01-20T10:43:55.788979Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::90
2023-01-20T10:43:55.788988Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.788995Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.789001Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [232, 33, 11, 94, 120, 49, 22, 43, 160, 166, 55, 129, 4, 241, 170, 185, 131, 54, 218, 157, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([225, 238, 158, 198, 199, 137, 8, 97, 185, 67, 160, 127, 119, 163, 164, 92, 239, 8, 248, 230]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.792910Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12352553,
    events_root: None,
}
2023-01-20T10:43:55.792991Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 91
2023-01-20T10:43:55.793043Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::91
2023-01-20T10:43:55.793052Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.793062Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.793070Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [79, 28, 48, 6, 69, 250, 96, 100, 249, 190, 126, 231, 156, 57, 137, 85, 59, 237, 9, 217, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([40, 80, 7, 100, 179, 140, 229, 153, 27, 223, 230, 101, 202, 1, 70, 47, 242, 104, 48, 7]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.796576Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12177836,
    events_root: None,
}
2023-01-20T10:43:55.796628Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 92
2023-01-20T10:43:55.796656Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::92
2023-01-20T10:43:55.796663Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.796671Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.796677Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [159, 137, 238, 11, 157, 113, 236, 248, 172, 252, 166, 80, 169, 200, 151, 126, 76, 253, 79, 92, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([117, 80, 21, 32, 38, 68, 114, 59, 236, 156, 92, 19, 239, 125, 17, 220, 1, 54, 208, 204]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.800175Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11787354,
    events_root: None,
}
2023-01-20T10:43:55.800232Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 93
2023-01-20T10:43:55.800266Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::93
2023-01-20T10:43:55.800274Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.800281Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.800287Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [187, 3, 185, 185, 100, 241, 237, 206, 18, 115, 142, 2, 166, 64, 144, 246, 18, 212, 199, 73, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([31, 100, 222, 111, 3, 64, 116, 117, 72, 255, 201, 98, 104, 128, 244, 234, 58, 79, 189, 62]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.803649Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11340219,
    events_root: None,
}
2023-01-20T10:43:55.803703Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 94
2023-01-20T10:43:55.803742Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::94
2023-01-20T10:43:55.803754Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.803764Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.803774Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [124, 142, 232, 32, 176, 24, 101, 72, 97, 12, 146, 93, 26, 140, 196, 79, 83, 109, 233, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([96, 221, 7, 113, 89, 247, 138, 119, 225, 55, 135, 221, 132, 165, 82, 22, 202, 208, 233, 91]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.807548Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10958796,
    events_root: None,
}
2023-01-20T10:43:55.807610Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 95
2023-01-20T10:43:55.807651Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::95
2023-01-20T10:43:55.807659Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.807667Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.807673Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [13, 72, 170, 99, 192, 17, 101, 7, 146, 218, 219, 153, 142, 33, 20, 74, 182, 54, 136, 70, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([155, 48, 90, 18, 221, 116, 7, 27, 31, 161, 14, 26, 47, 29, 244, 108, 165, 178, 172, 107]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.811623Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11792296,
    events_root: None,
}
2023-01-20T10:43:55.811721Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 96
2023-01-20T10:43:55.811777Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::96
2023-01-20T10:43:55.811785Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.811792Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.811799Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [129, 51, 58, 5, 234, 9, 129, 148, 57, 55, 219, 127, 247, 106, 126, 110, 200, 8, 14, 74, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([119, 4, 145, 93, 73, 93, 109, 235, 174, 220, 80, 34, 135, 115, 159, 83, 251, 51, 62, 194]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.815517Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11260321,
    events_root: None,
}
2023-01-20T10:43:55.815588Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 97
2023-01-20T10:43:55.815633Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::97
2023-01-20T10:43:55.815641Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.815648Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.815655Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [189, 72, 207, 204, 188, 82, 96, 81, 63, 233, 168, 65, 58, 206, 154, 155, 12, 29, 242, 222, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([88, 135, 6, 16, 62, 111, 126, 121, 88, 155, 35, 12, 237, 236, 216, 103, 21, 167, 148, 17]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.819376Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11311818,
    events_root: None,
}
2023-01-20T10:43:55.819430Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 98
2023-01-20T10:43:55.819463Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::98
2023-01-20T10:43:55.819471Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.819478Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.819484Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [198, 71, 146, 207, 217, 254, 248, 150, 247, 163, 44, 108, 240, 250, 208, 218, 146, 110, 205, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([42, 76, 99, 23, 230, 105, 11, 148, 115, 193, 49, 201, 172, 238, 44, 177, 35, 167, 102, 62]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.823290Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12105659,
    events_root: None,
}
2023-01-20T10:43:55.823397Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 99
2023-01-20T10:43:55.823455Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::99
2023-01-20T10:43:55.823464Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.823472Z  INFO evm_eth_compliance::statetest::runner: TX len : 77
2023-01-20T10:43:55.823478Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [236, 48, 29, 95, 238, 71, 210, 26, 236, 101, 128, 90, 217, 87, 3, 111, 124, 7, 187, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([119, 145, 84, 64, 213, 27, 134, 173, 52, 245, 118, 171, 99, 148, 112, 180, 105, 70, 113, 93]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.827537Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12296399,
    events_root: None,
}
2023-01-20T10:43:55.827611Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 100
2023-01-20T10:43:55.827664Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::100
2023-01-20T10:43:55.827672Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.827680Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.827687Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [75, 28, 131, 3, 79, 18, 70, 178, 211, 136, 249, 32, 194, 208, 38, 28, 109, 154, 174, 235, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([29, 140, 230, 138, 107, 84, 150, 22, 173, 23, 154, 28, 236, 246, 46, 198, 72, 180, 189, 9]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.831027Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10432219,
    events_root: None,
}
2023-01-20T10:43:55.831107Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 101
2023-01-20T10:43:55.831157Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::101
2023-01-20T10:43:55.831168Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.831179Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.831188Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [112, 32, 2, 203, 254, 142, 45, 4, 123, 221, 182, 67, 219, 166, 68, 99, 57, 62, 200, 192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([18, 27, 2, 121, 157, 192, 163, 52, 201, 162, 159, 21, 26, 224, 61, 97, 216, 253, 235, 163]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.834985Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11448773,
    events_root: None,
}
2023-01-20T10:43:55.835069Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 102
2023-01-20T10:43:55.835119Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::102
2023-01-20T10:43:55.835128Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.835135Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.835142Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [184, 8, 50, 132, 167, 140, 42, 131, 60, 25, 63, 170, 188, 221, 140, 220, 97, 171, 39, 75, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([251, 148, 47, 146, 203, 69, 25, 195, 112, 159, 197, 4, 200, 234, 86, 36, 129, 72, 237, 154]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.838869Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11354896,
    events_root: None,
}
2023-01-20T10:43:55.838966Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 103
2023-01-20T10:43:55.839028Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::103
2023-01-20T10:43:55.839038Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.839045Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.839052Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [39, 84, 186, 155, 190, 196, 127, 224, 117, 64, 142, 189, 157, 77, 89, 224, 14, 44, 133, 223, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([0, 139, 20, 138, 169, 250, 202, 38, 0, 219, 54, 113, 39, 208, 211, 109, 45, 57, 7, 29]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.842863Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10989961,
    events_root: None,
}
2023-01-20T10:43:55.842928Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 104
2023-01-20T10:43:55.842974Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::104
2023-01-20T10:43:55.842982Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.842989Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.842995Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [56, 251, 152, 112, 255, 105, 148, 115, 139, 234, 232, 44, 17, 226, 176, 232, 194, 240, 150, 249, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([131, 21, 199, 119, 4, 1, 184, 120, 124, 242, 219, 243, 79, 251, 176, 103, 61, 174, 128, 243]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.846471Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12214207,
    events_root: None,
}
2023-01-20T10:43:55.846523Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 105
2023-01-20T10:43:55.846552Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::105
2023-01-20T10:43:55.846559Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.846566Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.846572Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [10, 73, 70, 100, 106, 151, 81, 90, 0, 49, 131, 248, 7, 238, 5, 244, 93, 9, 243, 253, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([100, 203, 6, 94, 91, 68, 100, 181, 149, 221, 44, 86, 222, 158, 169, 227, 218, 136, 249, 75]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.850188Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11330545,
    events_root: None,
}
2023-01-20T10:43:55.850240Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 106
2023-01-20T10:43:55.850274Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::106
2023-01-20T10:43:55.850281Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.850288Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.850294Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [104, 56, 36, 224, 88, 198, 94, 31, 101, 91, 206, 196, 4, 125, 255, 170, 81, 184, 223, 41, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([26, 240, 28, 195, 132, 99, 78, 96, 33, 68, 142, 205, 74, 246, 255, 91, 152, 252, 192, 155]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.853794Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10431607,
    events_root: None,
}
2023-01-20T10:43:55.853846Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 107
2023-01-20T10:43:55.853878Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::107
2023-01-20T10:43:55.853885Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.853892Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.853899Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [207, 105, 59, 182, 254, 120, 89, 52, 156, 12, 232, 73, 33, 195, 194, 249, 34, 93, 138, 63, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([80, 121, 104, 125, 93, 227, 237, 85, 56, 27, 105, 5, 43, 95, 74, 142, 141, 225, 238, 47]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.857594Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12137918,
    events_root: None,
}
2023-01-20T10:43:55.857675Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 108
2023-01-20T10:43:55.857728Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::108
2023-01-20T10:43:55.857740Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.857751Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.857760Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [21, 43, 229, 62, 127, 92, 53, 36, 36, 218, 99, 5, 80, 102, 195, 231, 7, 3, 159, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([95, 70, 69, 70, 176, 49, 182, 243, 189, 49, 50, 205, 114, 117, 90, 14, 54, 147, 219, 141]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.861360Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11334397,
    events_root: None,
}
2023-01-20T10:43:55.861414Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 109
2023-01-20T10:43:55.861450Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::109
2023-01-20T10:43:55.861457Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.861464Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.861470Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [85, 126, 88, 1, 146, 245, 114, 198, 160, 163, 210, 5, 230, 167, 255, 228, 95, 104, 56, 21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([2, 29, 119, 133, 104, 132, 91, 37, 255, 242, 99, 245, 110, 126, 96, 115, 141, 115, 78, 231]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.865052Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12156013,
    events_root: None,
}
2023-01-20T10:43:55.865111Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 110
2023-01-20T10:43:55.865145Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::110
2023-01-20T10:43:55.865153Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.865160Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.865166Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [232, 109, 234, 237, 42, 171, 70, 69, 254, 30, 31, 192, 26, 88, 160, 239, 134, 55, 187, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([166, 111, 150, 7, 151, 203, 163, 23, 193, 47, 73, 19, 21, 71, 28, 22, 47, 225, 171, 163]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.868483Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10970553,
    events_root: None,
}
2023-01-20T10:43:55.868536Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 111
2023-01-20T10:43:55.868567Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::111
2023-01-20T10:43:55.868575Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.868582Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.868588Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [109, 62, 171, 117, 208, 167, 230, 65, 129, 92, 184, 152, 62, 64, 177, 187, 131, 207, 18, 240, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([227, 33, 40, 41, 106, 100, 194, 98, 93, 91, 102, 65, 34, 228, 239, 113, 118, 110, 188, 163]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.872083Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12094207,
    events_root: None,
}
2023-01-20T10:43:55.872140Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 112
2023-01-20T10:43:55.872174Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::112
2023-01-20T10:43:55.872181Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.872188Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-20T10:43:55.872196Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [81, 64, 100, 209, 7, 163, 177, 125, 88, 3, 39, 34, 220, 207, 239, 202, 138, 140, 144, 207, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([238, 67, 40, 127, 153, 170, 231, 31, 27, 189, 74, 95, 145, 13, 91, 152, 106, 149, 37, 30]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.876126Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12191471,
    events_root: None,
}
2023-01-20T10:43:55.876194Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 113
2023-01-20T10:43:55.876240Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::113
2023-01-20T10:43:55.876248Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.876255Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:43:55.876261Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [107, 109, 69, 9, 178, 213, 48, 168, 9, 201, 160, 244, 58, 11, 112, 108, 239, 70, 178, 67, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([21, 40, 14, 38, 252, 118, 66, 103, 98, 150, 252, 118, 196, 220, 120, 14, 191, 136, 175, 22]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.879586Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10955541,
    events_root: None,
}
2023-01-20T10:43:55.879638Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 114
2023-01-20T10:43:55.879669Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::114
2023-01-20T10:43:55.879676Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.879684Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:43:55.879690Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [42, 158, 119, 77, 3, 94, 60, 53, 25, 101, 233, 208, 15, 235, 85, 19, 64, 126, 205, 56, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([23, 195, 35, 199, 237, 215, 9, 133, 138, 169, 41, 41, 21, 140, 61, 47, 131, 109, 202, 227]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.883096Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11311657,
    events_root: None,
}
2023-01-20T10:43:55.883152Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 115
2023-01-20T10:43:55.883187Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::115
2023-01-20T10:43:55.883195Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.883202Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:43:55.883208Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [30, 240, 209, 157, 218, 107, 102, 156, 113, 194, 241, 149, 104, 150, 84, 23, 103, 35, 159, 127, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([246, 154, 244, 177, 203, 194, 213, 20, 114, 118, 61, 213, 14, 253, 29, 3, 171, 95, 81, 165]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.886543Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11264997,
    events_root: None,
}
2023-01-20T10:43:55.886595Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 116
2023-01-20T10:43:55.886623Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::116
2023-01-20T10:43:55.886630Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.886637Z  INFO evm_eth_compliance::statetest::runner: TX len : 33
2023-01-20T10:43:55.886643Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [54, 37, 173, 217, 60, 151, 67, 7, 186, 69, 135, 191, 207, 37, 200, 136, 203, 1, 246, 42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([125, 142, 180, 67, 30, 195, 115, 147, 46, 53, 0, 167, 68, 199, 138, 215, 197, 146, 77, 23]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.889904Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10437319,
    events_root: None,
}
2023-01-20T10:43:55.889971Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 117
2023-01-20T10:43:55.890010Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::117
2023-01-20T10:43:55.890018Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.890025Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:43:55.890031Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [238, 251, 137, 51, 42, 111, 77, 127, 87, 71, 153, 51, 247, 143, 235, 58, 20, 22, 67, 148, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([177, 249, 71, 16, 94, 5, 7, 223, 202, 108, 158, 33, 121, 14, 250, 246, 50, 245, 3, 253]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.893790Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12232313,
    events_root: None,
}
2023-01-20T10:43:55.893852Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 118
2023-01-20T10:43:55.893893Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::118
2023-01-20T10:43:55.893904Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.893911Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:43:55.893917Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [9, 90, 178, 50, 170, 75, 89, 152, 178, 153, 214, 181, 59, 102, 101, 183, 111, 246, 9, 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([2, 180, 255, 222, 75, 104, 55, 64, 26, 55, 66, 244, 63, 138, 191, 90, 119, 72, 198, 78]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.897418Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11834337,
    events_root: None,
}
2023-01-20T10:43:55.897472Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 119
2023-01-20T10:43:55.897503Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::119
2023-01-20T10:43:55.897510Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.897517Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:43:55.897523Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [182, 182, 248, 218, 221, 30, 199, 142, 183, 183, 102, 42, 181, 178, 40, 192, 93, 69, 245, 162, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([149, 187, 226, 191, 13, 68, 76, 32, 90, 2, 76, 3, 240, 217, 5, 67, 149, 177, 111, 250]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.900900Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11265380,
    events_root: None,
}
2023-01-20T10:43:55.900957Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 120
2023-01-20T10:43:55.900987Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::120
2023-01-20T10:43:55.900994Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.901001Z  INFO evm_eth_compliance::statetest::runner: TX len : 34
2023-01-20T10:43:55.901007Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [221, 15, 56, 217, 127, 245, 131, 105, 39, 219, 81, 74, 149, 134, 47, 42, 243, 246, 249, 46, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([135, 155, 16, 115, 107, 83, 219, 96, 57, 81, 173, 154, 223, 235, 119, 252, 35, 123, 158, 8]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.904147Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10437935,
    events_root: None,
}
2023-01-20T10:43:55.904196Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 121
2023-01-20T10:43:55.904224Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::121
2023-01-20T10:43:55.904231Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.904238Z  INFO evm_eth_compliance::statetest::runner: TX len : 35
2023-01-20T10:43:55.904244Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [224, 90, 170, 105, 223, 16, 168, 217, 101, 0, 114, 7, 97, 192, 105, 193, 238, 138, 230, 103, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 180, 189, 234, 113, 120, 190, 163, 101, 172, 135, 223, 102, 86, 69, 171, 195, 191, 48, 248]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.908011Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12220949,
    events_root: None,
}
2023-01-20T10:43:55.908096Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 122
2023-01-20T10:43:55.908147Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::122
2023-01-20T10:43:55.908156Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.908163Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-20T10:43:55.908169Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [57, 46, 48, 106, 9, 113, 92, 52, 55, 122, 236, 225, 190, 45, 77, 188, 20, 113, 248, 88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([6, 122, 253, 222, 35, 73, 130, 165, 2, 129, 148, 135, 157, 66, 77, 31, 233, 24, 38, 118]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.911731Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11781717,
    events_root: None,
}
2023-01-20T10:43:55.911783Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 123
2023-01-20T10:43:55.911813Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::123
2023-01-20T10:43:55.911820Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.911827Z  INFO evm_eth_compliance::statetest::runner: TX len : 38
2023-01-20T10:43:55.911833Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [23, 99, 22, 205, 223, 114, 21, 236, 183, 37, 187, 65, 171, 186, 194, 227, 139, 119, 230, 125, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([77, 179, 37, 229, 81, 207, 123, 87, 60, 115, 156, 105, 136, 92, 146, 11, 86, 211, 213, 140]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.915155Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11260057,
    events_root: None,
}
2023-01-20T10:43:55.915205Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 124
2023-01-20T10:43:55.915234Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::124
2023-01-20T10:43:55.915241Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.915248Z  INFO evm_eth_compliance::statetest::runner: TX len : 39
2023-01-20T10:43:55.915254Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [1, 19, 100, 133, 102, 191, 180, 14, 143, 103, 254, 214, 150, 68, 178, 163, 140, 67, 173, 204, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([159, 89, 244, 97, 216, 246, 171, 160, 194, 159, 249, 175, 143, 250, 196, 14, 37, 21, 116, 148]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.918461Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10483079,
    events_root: None,
}
2023-01-20T10:43:55.918524Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 125
2023-01-20T10:43:55.918556Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::125
2023-01-20T10:43:55.918564Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.918571Z  INFO evm_eth_compliance::statetest::runner: TX len : 40
2023-01-20T10:43:55.918577Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [251, 153, 154, 110, 101, 101, 145, 42, 9, 229, 195, 210, 114, 190, 114, 222, 167, 19, 145, 176, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([81, 80, 28, 154, 255, 53, 201, 25, 240, 13, 78, 24, 7, 243, 215, 88, 230, 75, 209, 72]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.922061Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12178551,
    events_root: None,
}
2023-01-20T10:43:55.922114Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 126
2023-01-20T10:43:55.922144Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::126
2023-01-20T10:43:55.922151Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.922158Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:55.922165Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 144, 73, 29, 205, 127, 156, 203, 59, 251, 149, 35, 227, 239, 139, 240, 218, 215, 101, 188, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([156, 171, 158, 121, 236, 77, 77, 104, 97, 93, 182, 60, 124, 79, 216, 70, 25, 4, 156, 250]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.926068Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11267909,
    events_root: None,
}
2023-01-20T10:43:55.926137Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 127
2023-01-20T10:43:55.926185Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::127
2023-01-20T10:43:55.926194Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.926201Z  INFO evm_eth_compliance::statetest::runner: TX len : 42
2023-01-20T10:43:55.926207Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [105, 4, 95, 139, 78, 175, 45, 221, 68, 199, 172, 198, 239, 93, 234, 171, 94, 138, 5, 189, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([41, 144, 215, 158, 252, 240, 131, 109, 15, 144, 3, 221, 34, 42, 228, 35, 224, 218, 9, 210]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.929669Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12106531,
    events_root: None,
}
2023-01-20T10:43:55.929720Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 128
2023-01-20T10:43:55.929749Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::128
2023-01-20T10:43:55.929756Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.929763Z  INFO evm_eth_compliance::statetest::runner: TX len : 45
2023-01-20T10:43:55.929769Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [132, 84, 238, 173, 37, 167, 106, 208, 59, 224, 193, 156, 186, 170, 18, 147, 7, 55, 251, 121, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([54, 140, 199, 165, 133, 117, 18, 215, 66, 153, 234, 211, 197, 77, 137, 96, 114, 167, 13, 75]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.933216Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12195309,
    events_root: None,
}
2023-01-20T10:43:55.933268Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 129
2023-01-20T10:43:55.933296Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::129
2023-01-20T10:43:55.933302Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.933309Z  INFO evm_eth_compliance::statetest::runner: TX len : 50
2023-01-20T10:43:55.933315Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [155, 160, 97, 21, 249, 41, 233, 153, 3, 195, 248, 164, 76, 187, 195, 103, 7, 90, 54, 65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([239, 165, 144, 40, 183, 72, 233, 8, 233, 179, 217, 27, 205, 204, 157, 197, 219, 127, 14, 35]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.936563Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10480055,
    events_root: None,
}
2023-01-20T10:43:55.936616Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 130
2023-01-20T10:43:55.936648Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::130
2023-01-20T10:43:55.936655Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.936662Z  INFO evm_eth_compliance::statetest::runner: TX len : 50
2023-01-20T10:43:55.936668Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [63, 112, 57, 179, 73, 126, 181, 135, 167, 198, 42, 134, 159, 37, 25, 125, 150, 105, 2, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([145, 39, 57, 40, 244, 97, 114, 211, 157, 178, 230, 42, 204, 136, 110, 218, 94, 3, 133, 15]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.940173Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11259920,
    events_root: None,
}
2023-01-20T10:43:55.940269Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 131
2023-01-20T10:43:55.940323Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::131
2023-01-20T10:43:55.940333Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.940342Z  INFO evm_eth_compliance::statetest::runner: TX len : 48
2023-01-20T10:43:55.940350Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [160, 189, 204, 214, 83, 90, 189, 73, 148, 69, 148, 129, 135, 126, 19, 44, 236, 215, 76, 141, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([43, 121, 247, 50, 237, 37, 132, 48, 70, 152, 225, 148, 95, 26, 219, 87, 32, 242, 98, 90]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.944234Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12172424,
    events_root: None,
}
2023-01-20T10:43:55.944292Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 132
2023-01-20T10:43:55.944332Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::132
2023-01-20T10:43:55.944339Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.944347Z  INFO evm_eth_compliance::statetest::runner: TX len : 46
2023-01-20T10:43:55.944353Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [199, 194, 89, 92, 173, 21, 44, 109, 214, 3, 48, 34, 252, 6, 55, 153, 164, 226, 52, 198, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([184, 255, 181, 20, 221, 252, 201, 27, 63, 8, 16, 146, 19, 110, 18, 158, 84, 214, 49, 125]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.947749Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11330298,
    events_root: None,
}
2023-01-20T10:43:55.947804Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 133
2023-01-20T10:43:55.947835Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::133
2023-01-20T10:43:55.947842Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.947849Z  INFO evm_eth_compliance::statetest::runner: TX len : 44
2023-01-20T10:43:55.947856Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [180, 48, 72, 205, 175, 7, 228, 162, 165, 2, 246, 54, 210, 101, 189, 201, 175, 80, 122, 146, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([5, 105, 242, 156, 75, 161, 251, 173, 228, 244, 156, 55, 159, 15, 30, 21, 129, 208, 49, 115]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.951399Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11791637,
    events_root: None,
}
2023-01-20T10:43:55.951461Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 134
2023-01-20T10:43:55.951498Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::134
2023-01-20T10:43:55.951505Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.951512Z  INFO evm_eth_compliance::statetest::runner: TX len : 47
2023-01-20T10:43:55.951519Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [75, 254, 65, 85, 139, 189, 118, 38, 178, 126, 87, 13, 139, 142, 230, 32, 143, 60, 151, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 183, 224, 215, 231, 71, 205, 164, 221, 233, 232, 111, 213, 234, 70, 82, 92, 231, 191, 172]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.954997Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12188032,
    events_root: None,
}
2023-01-20T10:43:55.955049Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 135
2023-01-20T10:43:55.955079Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::135
2023-01-20T10:43:55.955087Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.955094Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:43:55.955100Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [160, 68, 84, 73, 228, 155, 116, 198, 50, 101, 15, 192, 169, 48, 106, 106, 158, 167, 255, 156, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([165, 61, 106, 15, 46, 11, 223, 246, 4, 93, 31, 89, 52, 0, 67, 121, 23, 247, 59, 138]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.959135Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11954188,
    events_root: None,
}
2023-01-20T10:43:55.959216Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 136
2023-01-20T10:43:55.959265Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::136
2023-01-20T10:43:55.959274Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.959282Z  INFO evm_eth_compliance::statetest::runner: TX len : 58
2023-01-20T10:43:55.959288Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [9, 114, 161, 216, 249, 187, 150, 100, 203, 209, 38, 41, 74, 55, 103, 224, 245, 82, 13, 249, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([166, 33, 73, 89, 43, 117, 95, 36, 123, 177, 163, 118, 200, 201, 50, 148, 185, 37, 107, 154]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.962675Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11250240,
    events_root: None,
}
2023-01-20T10:43:55.962726Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 137
2023-01-20T10:43:55.962755Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::137
2023-01-20T10:43:55.962765Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.962774Z  INFO evm_eth_compliance::statetest::runner: TX len : 50
2023-01-20T10:43:55.962782Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [57, 132, 182, 100, 210, 121, 111, 195, 95, 229, 8, 56, 86, 13, 227, 224, 153, 150, 213, 224, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([148, 193, 25, 127, 138, 190, 135, 142, 9, 94, 134, 72, 116, 183, 208, 145, 89, 123, 125, 176]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.966370Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12252654,
    events_root: None,
}
2023-01-20T10:43:55.966432Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 138
2023-01-20T10:43:55.966469Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::138
2023-01-20T10:43:55.966477Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.966484Z  INFO evm_eth_compliance::statetest::runner: TX len : 50
2023-01-20T10:43:55.966490Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [242, 103, 80, 61, 86, 47, 23, 127, 51, 240, 124, 14, 87, 2, 235, 115, 230, 0, 25, 244, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([123, 226, 50, 52, 222, 73, 76, 23, 47, 7, 197, 161, 190, 22, 190, 175, 154, 153, 133, 213]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.969721Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10447898,
    events_root: None,
}
2023-01-20T10:43:55.969775Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 139
2023-01-20T10:43:55.969808Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::139
2023-01-20T10:43:55.969815Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.969822Z  INFO evm_eth_compliance::statetest::runner: TX len : 44
2023-01-20T10:43:55.969829Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [209, 211, 4, 34, 208, 31, 85, 216, 169, 231, 211, 61, 53, 10, 244, 210, 242, 236, 18, 150, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([206, 5, 126, 171, 226, 44, 99, 187, 109, 146, 70, 233, 204, 42, 34, 178, 199, 101, 125, 42]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.973568Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11775204,
    events_root: None,
}
2023-01-20T10:43:55.973669Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 140
2023-01-20T10:43:55.973723Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::140
2023-01-20T10:43:55.973731Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.973740Z  INFO evm_eth_compliance::statetest::runner: TX len : 52
2023-01-20T10:43:55.973746Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [119, 73, 10, 232, 142, 196, 53, 51, 21, 160, 177, 98, 227, 122, 83, 24, 107, 104, 226, 217, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([229, 134, 218, 28, 173, 120, 102, 217, 86, 17, 87, 148, 11, 132, 141, 172, 158, 89, 43, 245]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.977666Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11855533,
    events_root: None,
}
2023-01-20T10:43:55.977730Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 141
2023-01-20T10:43:55.977777Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::141
2023-01-20T10:43:55.977784Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.977791Z  INFO evm_eth_compliance::statetest::runner: TX len : 53
2023-01-20T10:43:55.977797Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [229, 8, 160, 11, 25, 142, 184, 33, 27, 153, 253, 143, 153, 91, 97, 67, 15, 101, 119, 219, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([223, 202, 140, 233, 184, 139, 245, 92, 60, 253, 237, 185, 78, 222, 238, 205, 254, 61, 116, 112]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.981412Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12257986,
    events_root: None,
}
2023-01-20T10:43:55.981489Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 142
2023-01-20T10:43:55.981535Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::142
2023-01-20T10:43:55.981544Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.981553Z  INFO evm_eth_compliance::statetest::runner: TX len : 53
2023-01-20T10:43:55.981561Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [235, 20, 8, 23, 118, 43, 143, 126, 150, 119, 176, 119, 255, 248, 95, 165, 172, 49, 248, 85, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([27, 47, 20, 62, 115, 89, 64, 100, 228, 180, 154, 197, 75, 89, 74, 3, 65, 136, 122, 18]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.985123Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12180262,
    events_root: None,
}
2023-01-20T10:43:55.985184Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 143
2023-01-20T10:43:55.985222Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::143
2023-01-20T10:43:55.985230Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.985237Z  INFO evm_eth_compliance::statetest::runner: TX len : 53
2023-01-20T10:43:55.985243Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [61, 22, 178, 200, 192, 113, 6, 107, 240, 94, 199, 30, 180, 171, 97, 205, 208, 255, 28, 158, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([149, 71, 225, 67, 173, 140, 14, 147, 102, 27, 208, 141, 97, 205, 181, 63, 253, 204, 193, 100]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.988869Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11880279,
    events_root: None,
}
2023-01-20T10:43:55.988976Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 144
2023-01-20T10:43:55.989036Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::144
2023-01-20T10:43:55.989050Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.989060Z  INFO evm_eth_compliance::statetest::runner: TX len : 47
2023-01-20T10:43:55.989066Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [122, 44, 252, 50, 92, 164, 5, 45, 52, 85, 116, 185, 3, 250, 101, 219, 210, 40, 252, 97, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([137, 145, 54, 83, 246, 51, 78, 58, 91, 216, 106, 48, 128, 183, 231, 127, 217, 76, 111, 78]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.992984Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12140423,
    events_root: None,
}
2023-01-20T10:43:55.993044Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 145
2023-01-20T10:43:55.993085Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::145
2023-01-20T10:43:55.993092Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.993100Z  INFO evm_eth_compliance::statetest::runner: TX len : 48
2023-01-20T10:43:55.993106Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [12, 222, 212, 136, 223, 118, 70, 250, 54, 157, 99, 176, 192, 112, 41, 88, 245, 236, 36, 115, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([159, 71, 60, 185, 123, 210, 99, 236, 135, 165, 57, 125, 84, 113, 104, 125, 111, 150, 82, 231]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.996573Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12255774,
    events_root: None,
}
2023-01-20T10:43:55.996625Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 146
2023-01-20T10:43:55.996652Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::146
2023-01-20T10:43:55.996659Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:55.996666Z  INFO evm_eth_compliance::statetest::runner: TX len : 43
2023-01-20T10:43:55.996672Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [218, 146, 5, 159, 139, 146, 111, 14, 240, 145, 194, 253, 128, 5, 68, 16, 100, 96, 254, 220, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([9, 224, 232, 168, 153, 181, 62, 58, 189, 119, 63, 170, 224, 170, 186, 134, 128, 166, 153, 2]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:55.999909Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10472362,
    events_root: None,
}
2023-01-20T10:43:55.999961Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 147
2023-01-20T10:43:55.999992Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::147
2023-01-20T10:43:55.999999Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.000006Z  INFO evm_eth_compliance::statetest::runner: TX len : 44
2023-01-20T10:43:56.000012Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [198, 249, 246, 158, 116, 109, 23, 60, 58, 7, 116, 234, 69, 238, 194, 170, 32, 101, 199, 239, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([72, 105, 66, 48, 74, 19, 182, 9, 127, 234, 99, 15, 143, 107, 125, 55, 183, 169, 1, 75]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.003267Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10964217,
    events_root: None,
}
2023-01-20T10:43:56.003318Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 148
2023-01-20T10:43:56.003347Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::148
2023-01-20T10:43:56.003354Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.003361Z  INFO evm_eth_compliance::statetest::runner: TX len : 45
2023-01-20T10:43:56.003367Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [50, 104, 83, 211, 167, 156, 193, 250, 3, 143, 3, 248, 66, 196, 252, 77, 241, 176, 90, 115, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([173, 13, 34, 169, 194, 222, 156, 216, 136, 151, 149, 175, 128, 183, 62, 242, 162, 66, 247, 154]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.007227Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11318568,
    events_root: None,
}
2023-01-20T10:43:56.007305Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 149
2023-01-20T10:43:56.007355Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::149
2023-01-20T10:43:56.007363Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.007371Z  INFO evm_eth_compliance::statetest::runner: TX len : 52
2023-01-20T10:43:56.007377Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [3, 212, 225, 190, 189, 24, 132, 188, 1, 207, 183, 197, 20, 79, 143, 140, 31, 136, 6, 222, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([131, 115, 166, 173, 188, 201, 114, 218, 180, 15, 32, 132, 97, 59, 168, 72, 199, 135, 26, 237]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.010653Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10438669,
    events_root: None,
}
2023-01-20T10:43:56.010699Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 150
2023-01-20T10:43:56.010727Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::150
2023-01-20T10:43:56.010734Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.010741Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:43:56.010747Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [79, 212, 226, 135, 126, 38, 143, 29, 157, 120, 96, 193, 83, 56, 244, 148, 68, 96, 58, 115, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([18, 39, 234, 47, 187, 115, 16, 236, 114, 133, 188, 67, 197, 218, 58, 244, 8, 111, 45, 93]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.014181Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11791573,
    events_root: None,
}
2023-01-20T10:43:56.014231Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 151
2023-01-20T10:43:56.014262Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::151
2023-01-20T10:43:56.014272Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.014283Z  INFO evm_eth_compliance::statetest::runner: TX len : 54
2023-01-20T10:43:56.014291Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [171, 203, 253, 235, 151, 208, 45, 29, 147, 54, 158, 10, 188, 1, 88, 29, 187, 174, 76, 58, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([196, 252, 58, 192, 43, 102, 19, 227, 208, 48, 84, 217, 49, 54, 72, 20, 86, 249, 108, 199]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.017655Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11269796,
    events_root: None,
}
2023-01-20T10:43:56.017702Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 152
2023-01-20T10:43:56.017730Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::152
2023-01-20T10:43:56.017737Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.017745Z  INFO evm_eth_compliance::statetest::runner: TX len : 56
2023-01-20T10:43:56.017751Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [76, 196, 81, 90, 85, 152, 74, 202, 137, 250, 219, 53, 95, 175, 101, 110, 40, 117, 79, 108, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([104, 100, 146, 14, 168, 38, 124, 198, 79, 189, 132, 64, 2, 229, 247, 115, 204, 163, 78, 56]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.021239Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12319798,
    events_root: None,
}
2023-01-20T10:43:56.021295Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 153
2023-01-20T10:43:56.021328Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::153
2023-01-20T10:43:56.021335Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.021343Z  INFO evm_eth_compliance::statetest::runner: TX len : 58
2023-01-20T10:43:56.021349Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [135, 145, 224, 77, 69, 202, 106, 96, 111, 178, 134, 249, 210, 223, 237, 74, 5, 141, 110, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([248, 236, 36, 139, 209, 50, 63, 77, 176, 13, 235, 83, 117, 214, 72, 106, 36, 231, 224, 83]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.025332Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11854573,
    events_root: None,
}
2023-01-20T10:43:56.025402Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 154
2023-01-20T10:43:56.025448Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::154
2023-01-20T10:43:56.025456Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.025464Z  INFO evm_eth_compliance::statetest::runner: TX len : 65
2023-01-20T10:43:56.025470Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [26, 141, 96, 135, 164, 10, 199, 254, 39, 225, 131, 97, 38, 153, 168, 150, 56, 4, 79, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([36, 188, 161, 83, 225, 149, 170, 173, 187, 199, 21, 89, 135, 233, 104, 124, 133, 104, 36, 47]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.028818Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11248856,
    events_root: None,
}
2023-01-20T10:43:56.028865Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 155
2023-01-20T10:43:56.028893Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::155
2023-01-20T10:43:56.028899Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.028906Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.028913Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [141, 79, 139, 145, 58, 26, 66, 198, 27, 214, 30, 165, 74, 19, 35, 122, 10, 236, 93, 229, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([66, 65, 152, 213, 159, 82, 223, 248, 171, 98, 8, 190, 84, 85, 124, 203, 165, 140, 121, 165]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.032403Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11872119,
    events_root: None,
}
2023-01-20T10:43:56.032458Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 156
2023-01-20T10:43:56.032488Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::156
2023-01-20T10:43:56.032495Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.032502Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.032508Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [159, 40, 205, 230, 11, 114, 185, 24, 88, 212, 212, 226, 214, 55, 161, 162, 140, 19, 112, 136, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([245, 222, 198, 130, 175, 92, 183, 6, 115, 219, 17, 82, 10, 189, 100, 94, 176, 56, 53, 204]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.035901Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11783723,
    events_root: None,
}
2023-01-20T10:43:56.035953Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 157
2023-01-20T10:43:56.035981Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::157
2023-01-20T10:43:56.035988Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.035996Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.036002Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [58, 144, 200, 142, 99, 90, 19, 111, 33, 74, 139, 36, 102, 55, 147, 159, 129, 156, 82, 162, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([47, 143, 208, 29, 244, 71, 123, 233, 135, 174, 142, 22, 199, 133, 150, 66, 191, 126, 245, 105]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.039493Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12104992,
    events_root: None,
}
2023-01-20T10:43:56.039573Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 158
2023-01-20T10:43:56.039616Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::158
2023-01-20T10:43:56.039628Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.039638Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:43:56.039647Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [105, 226, 199, 26, 161, 131, 100, 225, 250, 246, 195, 222, 52, 92, 186, 191, 25, 201, 31, 187, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([9, 240, 5, 238, 205, 144, 121, 190, 117, 244, 171, 119, 221, 242, 93, 166, 187, 11, 249, 159]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.043583Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12192613,
    events_root: None,
}
2023-01-20T10:43:56.043647Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 159
2023-01-20T10:43:56.043690Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::159
2023-01-20T10:43:56.043698Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.043705Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:43:56.043711Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [90, 82, 189, 178, 125, 92, 80, 130, 99, 165, 10, 107, 59, 24, 11, 18, 73, 79, 12, 65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([127, 22, 74, 146, 31, 240, 94, 4, 5, 0, 168, 124, 152, 159, 106, 186, 166, 245, 96, 1]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.047140Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11853348,
    events_root: None,
}
2023-01-20T10:43:56.047207Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 160
2023-01-20T10:43:56.047247Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::160
2023-01-20T10:43:56.047260Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.047270Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:43:56.047281Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [168, 189, 113, 199, 49, 23, 128, 175, 227, 57, 106, 105, 250, 220, 143, 67, 16, 91, 238, 251, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([73, 61, 140, 212, 105, 148, 249, 14, 52, 230, 238, 162, 150, 154, 9, 21, 65, 159, 123, 114]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.050779Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12276344,
    events_root: None,
}
2023-01-20T10:43:56.050832Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 161
2023-01-20T10:43:56.050862Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::161
2023-01-20T10:43:56.050869Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.050876Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:43:56.050882Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [251, 16, 10, 35, 56, 130, 207, 93, 65, 190, 140, 183, 219, 67, 14, 25, 129, 197, 100, 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([139, 5, 231, 32, 229, 212, 4, 215, 238, 97, 99, 197, 170, 49, 135, 202, 113, 170, 126, 42]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.054346Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12182211,
    events_root: None,
}
2023-01-20T10:43:56.054400Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 162
2023-01-20T10:43:56.054431Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::162
2023-01-20T10:43:56.054438Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.054445Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:43:56.054451Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [97, 110, 6, 9, 76, 34, 60, 116, 111, 16, 229, 45, 94, 175, 65, 41, 7, 224, 120, 221, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([116, 63, 104, 161, 128, 157, 77, 211, 34, 225, 247, 206, 99, 136, 227, 1, 169, 47, 205, 63]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.058040Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10470758,
    events_root: None,
}
2023-01-20T10:43:56.058124Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 163
2023-01-20T10:43:56.058175Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::163
2023-01-20T10:43:56.058183Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.058190Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:43:56.058196Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [152, 55, 219, 11, 112, 180, 117, 247, 59, 130, 38, 147, 215, 73, 117, 37, 146, 196, 120, 68, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([24, 23, 0, 25, 83, 60, 59, 147, 214, 85, 44, 223, 55, 32, 220, 231, 144, 240, 221, 9]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.061636Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11273022,
    events_root: None,
}
2023-01-20T10:43:56.061687Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 164
2023-01-20T10:43:56.061716Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::164
2023-01-20T10:43:56.061723Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.061730Z  INFO evm_eth_compliance::statetest::runner: TX len : 55
2023-01-20T10:43:56.061735Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [124, 167, 66, 206, 108, 36, 226, 188, 125, 56, 213, 222, 230, 13, 22, 254, 247, 138, 225, 232, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([218, 18, 189, 93, 37, 195, 61, 200, 121, 174, 177, 80, 117, 158, 115, 198, 236, 94, 150, 60]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.065196Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12218612,
    events_root: None,
}
2023-01-20T10:43:56.065248Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 165
2023-01-20T10:43:56.065279Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::165
2023-01-20T10:43:56.065288Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.065296Z  INFO evm_eth_compliance::statetest::runner: TX len : 55
2023-01-20T10:43:56.065302Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [238, 202, 61, 171, 255, 134, 81, 68, 250, 174, 63, 199, 191, 124, 101, 58, 6, 147, 158, 252, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([185, 91, 157, 88, 96, 101, 55, 73, 90, 229, 142, 243, 119, 115, 114, 183, 43, 146, 80, 225]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.068624Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10956262,
    events_root: None,
}
2023-01-20T10:43:56.068677Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 166
2023-01-20T10:43:56.068707Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::166
2023-01-20T10:43:56.068714Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.068721Z  INFO evm_eth_compliance::statetest::runner: TX len : 55
2023-01-20T10:43:56.068727Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [25, 124, 154, 79, 255, 70, 130, 139, 23, 63, 184, 154, 212, 97, 4, 51, 249, 174, 33, 27, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([56, 243, 246, 92, 115, 19, 198, 26, 238, 116, 138, 85, 63, 113, 173, 50, 124, 171, 198, 175]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.072261Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12314214,
    events_root: None,
}
2023-01-20T10:43:56.072342Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 167
2023-01-20T10:43:56.072386Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::167
2023-01-20T10:43:56.072397Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.072407Z  INFO evm_eth_compliance::statetest::runner: TX len : 24
2023-01-20T10:43:56.072416Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [201, 12, 2, 105, 204, 132, 117, 100, 10, 154, 201, 118, 235, 37, 96, 57, 67, 169, 152, 67, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([73, 186, 110, 150, 243, 78, 194, 219, 28, 109, 164, 54, 87, 70, 183, 24, 19, 38, 68, 186]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.076338Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12182773,
    events_root: None,
}
2023-01-20T10:43:56.076403Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 168
2023-01-20T10:43:56.076446Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Merge::168
2023-01-20T10:43:56.076454Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.076462Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-20T10:43:56.076468Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [61, 197, 75, 236, 175, 56, 38, 22, 103, 139, 27, 119, 73, 214, 205, 43, 158, 62, 250, 248, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([233, 107, 20, 12, 37, 155, 50, 137, 233, 240, 196, 99, 127, 179, 80, 190, 4, 194, 225, 237]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.079907Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12201051,
    events_root: None,
}
2023-01-20T10:43:56.079962Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 0
2023-01-20T10:43:56.079990Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::0
2023-01-20T10:43:56.079998Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.080005Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-20T10:43:56.080011Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [101, 63, 173, 177, 44, 31, 177, 146, 133, 124, 94, 18, 167, 198, 254, 133, 39, 152, 146, 41, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 26, 191, 187, 28, 234, 77, 252, 28, 24, 75, 240, 211, 118, 185, 19, 78, 149, 70, 245]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.083403Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11256070,
    events_root: None,
}
2023-01-20T10:43:56.083456Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 1
2023-01-20T10:43:56.083487Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::1
2023-01-20T10:43:56.083494Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.083501Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:43:56.083507Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [228, 26, 47, 176, 191, 183, 28, 149, 87, 238, 230, 39, 95, 241, 20, 197, 239, 44, 79, 245, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([201, 38, 38, 22, 62, 219, 150, 135, 177, 241, 59, 153, 34, 29, 22, 107, 242, 108, 195, 135]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.086803Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11267812,
    events_root: None,
}
2023-01-20T10:43:56.086853Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 2
2023-01-20T10:43:56.086881Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::2
2023-01-20T10:43:56.086888Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.086896Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:43:56.086902Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [16, 86, 239, 220, 154, 118, 70, 93, 154, 230, 253, 67, 135, 235, 69, 43, 103, 78, 25, 103, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([145, 33, 89, 45, 120, 162, 235, 138, 158, 220, 105, 187, 248, 227, 88, 59, 111, 227, 175, 120]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.090480Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10975702,
    events_root: None,
}
2023-01-20T10:43:56.090591Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 3
2023-01-20T10:43:56.090650Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::3
2023-01-20T10:43:56.090664Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.090675Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:43:56.090684Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [194, 194, 242, 34, 10, 28, 73, 91, 254, 219, 32, 162, 211, 103, 45, 75, 197, 220, 230, 202, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([92, 78, 32, 183, 20, 116, 160, 24, 93, 13, 74, 60, 71, 47, 68, 214, 9, 69, 33, 242]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.094233Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11269116,
    events_root: None,
}
2023-01-20T10:43:56.094286Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 4
2023-01-20T10:43:56.094319Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::4
2023-01-20T10:43:56.094326Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.094333Z  INFO evm_eth_compliance::statetest::runner: TX len : 2
2023-01-20T10:43:56.094339Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [139, 96, 156, 212, 148, 202, 116, 37, 147, 122, 110, 232, 26, 60, 76, 140, 174, 84, 144, 89, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([29, 170, 11, 152, 113, 250, 63, 241, 164, 232, 205, 177, 191, 59, 170, 2, 166, 154, 6, 141]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.097603Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10952141,
    events_root: None,
}
2023-01-20T10:43:56.097671Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 5
2023-01-20T10:43:56.097711Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::5
2023-01-20T10:43:56.097722Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.097732Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:43:56.097740Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [96, 238, 169, 187, 54, 25, 2, 165, 221, 114, 126, 124, 31, 213, 194, 112, 227, 136, 75, 160, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([224, 127, 142, 26, 16, 56, 223, 204, 58, 154, 158, 13, 80, 107, 194, 252, 198, 89, 188, 114]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.101247Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10991972,
    events_root: None,
}
2023-01-20T10:43:56.101305Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 6
2023-01-20T10:43:56.101340Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::6
2023-01-20T10:43:56.101348Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.101355Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:43:56.101362Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [237, 151, 207, 130, 108, 170, 10, 118, 20, 128, 125, 86, 2, 17, 255, 6, 0, 216, 109, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([83, 242, 32, 232, 142, 92, 253, 105, 158, 39, 47, 205, 245, 242, 166, 27, 224, 56, 84, 129]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.104807Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12255616,
    events_root: None,
}
2023-01-20T10:43:56.104861Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 7
2023-01-20T10:43:56.104892Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::7
2023-01-20T10:43:56.104900Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.104907Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:43:56.104913Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [136, 213, 230, 162, 107, 139, 61, 240, 197, 169, 91, 253, 98, 89, 125, 17, 61, 145, 81, 117, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([32, 12, 253, 213, 163, 63, 29, 115, 178, 187, 161, 163, 212, 193, 125, 27, 3, 62, 7, 249]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.108971Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12191304,
    events_root: None,
}
2023-01-20T10:43:56.109054Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 8
2023-01-20T10:43:56.109101Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::8
2023-01-20T10:43:56.109110Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.109118Z  INFO evm_eth_compliance::statetest::runner: TX len : 3
2023-01-20T10:43:56.109124Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 234, 52, 211, 20, 105, 114, 239, 93, 71, 252, 147, 132, 203, 254, 70, 107, 44, 217, 211, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([10, 31, 101, 35, 215, 26, 74, 181, 210, 246, 179, 103, 102, 200, 253, 136, 135, 201, 30, 222]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.112478Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10942452,
    events_root: None,
}
2023-01-20T10:43:56.112528Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 9
2023-01-20T10:43:56.112556Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::9
2023-01-20T10:43:56.112563Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.112570Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T10:43:56.112576Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [62, 213, 240, 228, 117, 171, 107, 186, 224, 209, 198, 39, 71, 231, 153, 223, 239, 68, 213, 239, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([111, 101, 131, 235, 47, 251, 193, 19, 227, 95, 161, 71, 165, 135, 114, 55, 251, 221, 137, 48]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.115929Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10935453,
    events_root: None,
}
2023-01-20T10:43:56.115983Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 10
2023-01-20T10:43:56.116013Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::10
2023-01-20T10:43:56.116021Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.116028Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T10:43:56.116033Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [23, 94, 222, 159, 12, 179, 27, 15, 23, 195, 95, 181, 139, 232, 160, 254, 89, 114, 89, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([32, 102, 203, 126, 45, 108, 207, 145, 210, 218, 252, 249, 122, 133, 241, 60, 219, 42, 234, 109]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.119930Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11382100,
    events_root: None,
}
2023-01-20T10:43:56.119986Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 11
2023-01-20T10:43:56.120022Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::11
2023-01-20T10:43:56.120029Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.120037Z  INFO evm_eth_compliance::statetest::runner: TX len : 5
2023-01-20T10:43:56.120043Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [185, 35, 220, 198, 55, 91, 32, 169, 121, 175, 79, 243, 58, 8, 64, 40, 98, 22, 104, 72, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([196, 98, 194, 59, 213, 64, 206, 31, 14, 190, 130, 228, 239, 109, 211, 237, 18, 175, 83, 144]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.123947Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11263689,
    events_root: None,
}
2023-01-20T10:43:56.124037Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 12
2023-01-20T10:43:56.124090Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::12
2023-01-20T10:43:56.124098Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.124106Z  INFO evm_eth_compliance::statetest::runner: TX len : 7
2023-01-20T10:43:56.124112Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [65, 27, 80, 100, 239, 200, 189, 50, 34, 51, 51, 244, 14, 71, 110, 226, 15, 178, 27, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([71, 70, 230, 190, 48, 241, 157, 172, 217, 73, 0, 165, 128, 235, 16, 135, 37, 189, 190, 113]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.127616Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11440659,
    events_root: None,
}
2023-01-20T10:43:56.127667Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 13
2023-01-20T10:43:56.127696Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::13
2023-01-20T10:43:56.127703Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.127710Z  INFO evm_eth_compliance::statetest::runner: TX len : 8
2023-01-20T10:43:56.127716Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [238, 131, 224, 69, 105, 208, 78, 216, 175, 56, 27, 107, 190, 198, 218, 86, 16, 118, 114, 37, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([29, 74, 4, 136, 2, 197, 156, 124, 105, 58, 48, 79, 205, 124, 25, 157, 119, 224, 166, 125]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.131063Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11328576,
    events_root: None,
}
2023-01-20T10:43:56.131131Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 14
2023-01-20T10:43:56.131168Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::14
2023-01-20T10:43:56.131176Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.131183Z  INFO evm_eth_compliance::statetest::runner: TX len : 9
2023-01-20T10:43:56.131189Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [219, 163, 37, 201, 243, 165, 134, 68, 174, 86, 184, 136, 28, 137, 169, 133, 148, 170, 89, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([195, 245, 116, 142, 151, 66, 202, 110, 58, 159, 70, 222, 65, 77, 234, 43, 213, 48, 253, 205]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.134626Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11833482,
    events_root: None,
}
2023-01-20T10:43:56.134677Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 15
2023-01-20T10:43:56.134706Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::15
2023-01-20T10:43:56.134713Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.134720Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:43:56.134726Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [119, 232, 184, 232, 75, 17, 215, 223, 118, 235, 21, 102, 226, 192, 222, 177, 97, 77, 36, 106, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([204, 53, 98, 209, 229, 200, 215, 107, 227, 119, 179, 25, 140, 108, 161, 147, 169, 11, 20, 115]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.138034Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11258512,
    events_root: None,
}
2023-01-20T10:43:56.138086Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 16
2023-01-20T10:43:56.138118Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::16
2023-01-20T10:43:56.138125Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.138132Z  INFO evm_eth_compliance::statetest::runner: TX len : 11
2023-01-20T10:43:56.138138Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [250, 32, 201, 163, 21, 15, 203, 207, 30, 10, 165, 21, 145, 61, 67, 181, 110, 216, 33, 130, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([40, 178, 254, 193, 140, 79, 21, 80, 164, 98, 191, 21, 73, 18, 4, 43, 202, 172, 1, 184]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.142052Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10952157,
    events_root: None,
}
2023-01-20T10:43:56.142125Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 17
2023-01-20T10:43:56.142174Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::17
2023-01-20T10:43:56.142182Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.142189Z  INFO evm_eth_compliance::statetest::runner: TX len : 14
2023-01-20T10:43:56.142196Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [148, 23, 34, 188, 177, 215, 19, 72, 62, 47, 60, 27, 32, 110, 236, 236, 41, 216, 82, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([188, 234, 201, 49, 114, 108, 161, 6, 193, 42, 108, 44, 66, 95, 77, 32, 42, 210, 209, 216]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.145598Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11278053,
    events_root: None,
}
2023-01-20T10:43:56.145645Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 18
2023-01-20T10:43:56.145674Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::18
2023-01-20T10:43:56.145681Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.145688Z  INFO evm_eth_compliance::statetest::runner: TX len : 19
2023-01-20T10:43:56.145694Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [100, 58, 106, 20, 155, 206, 174, 73, 91, 26, 165, 231, 166, 97, 149, 148, 59, 168, 45, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([126, 43, 88, 164, 145, 22, 42, 161, 83, 26, 206, 54, 162, 199, 187, 115, 68, 241, 84, 138]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.149213Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11762756,
    events_root: None,
}
2023-01-20T10:43:56.149263Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 19
2023-01-20T10:43:56.149294Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::19
2023-01-20T10:43:56.149302Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.149309Z  INFO evm_eth_compliance::statetest::runner: TX len : 19
2023-01-20T10:43:56.149314Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [2, 65, 129, 167, 248, 136, 95, 103, 156, 140, 249, 242, 113, 108, 204, 144, 1, 0, 87, 27, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([147, 253, 123, 90, 174, 188, 203, 171, 110, 84, 239, 160, 222, 55, 66, 212, 224, 160, 168, 137]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.152767Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12147557,
    events_root: None,
}
2023-01-20T10:43:56.152816Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 20
2023-01-20T10:43:56.152844Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::20
2023-01-20T10:43:56.152850Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.152857Z  INFO evm_eth_compliance::statetest::runner: TX len : 17
2023-01-20T10:43:56.152863Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [49, 125, 157, 9, 255, 11, 112, 143, 133, 104, 122, 82, 183, 124, 139, 36, 189, 158, 196, 183, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([251, 38, 65, 156, 132, 234, 224, 205, 126, 248, 103, 225, 8, 124, 250, 208, 120, 32, 32, 107]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.156346Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12178963,
    events_root: None,
}
2023-01-20T10:43:56.156406Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 21
2023-01-20T10:43:56.156440Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::21
2023-01-20T10:43:56.156447Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.156454Z  INFO evm_eth_compliance::statetest::runner: TX len : 15
2023-01-20T10:43:56.156460Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [252, 225, 103, 231, 223, 36, 6, 47, 151, 93, 43, 217, 94, 200, 136, 41, 125, 177, 99, 54, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([49, 148, 229, 172, 111, 229, 44, 147, 138, 118, 204, 113, 64, 57, 137, 98, 223, 38, 83, 174]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.160222Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11329115,
    events_root: None,
}
2023-01-20T10:43:56.160280Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 22
2023-01-20T10:43:56.160323Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::22
2023-01-20T10:43:56.160330Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.160338Z  INFO evm_eth_compliance::statetest::runner: TX len : 13
2023-01-20T10:43:56.160343Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [197, 59, 249, 63, 249, 198, 12, 240, 113, 204, 1, 34, 199, 244, 164, 202, 237, 110, 91, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([187, 249, 92, 28, 16, 244, 165, 219, 119, 35, 12, 202, 251, 251, 48, 189, 74, 117, 48, 202]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.163756Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11261973,
    events_root: None,
}
2023-01-20T10:43:56.163807Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 23
2023-01-20T10:43:56.163842Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::23
2023-01-20T10:43:56.163849Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.163856Z  INFO evm_eth_compliance::statetest::runner: TX len : 19
2023-01-20T10:43:56.163863Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [222, 108, 200, 83, 218, 99, 93, 193, 176, 55, 63, 42, 214, 249, 34, 76, 178, 141, 45, 59, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([140, 186, 63, 49, 66, 240, 183, 54, 114, 98, 132, 22, 69, 6, 26, 220, 173, 196, 152, 247]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.167316Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11260000,
    events_root: None,
}
2023-01-20T10:43:56.167367Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 24
2023-01-20T10:43:56.167400Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::24
2023-01-20T10:43:56.167407Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.167414Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T10:43:56.167420Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [158, 85, 20, 203, 12, 62, 3, 209, 180, 222, 3, 22, 163, 182, 58, 136, 208, 254, 196, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([142, 13, 227, 162, 152, 49, 132, 37, 0, 216, 235, 214, 250, 28, 70, 110, 17, 135, 202, 215]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.170766Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11323982,
    events_root: None,
}
2023-01-20T10:43:56.170817Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 25
2023-01-20T10:43:56.170850Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::25
2023-01-20T10:43:56.170857Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.170864Z  INFO evm_eth_compliance::statetest::runner: TX len : 27
2023-01-20T10:43:56.170870Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [249, 230, 206, 132, 97, 249, 62, 185, 233, 160, 229, 38, 18, 90, 2, 11, 90, 230, 45, 59, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([118, 42, 175, 165, 200, 193, 115, 136, 184, 109, 233, 62, 122, 51, 84, 247, 101, 182, 24, 20]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.174471Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10953708,
    events_root: None,
}
2023-01-20T10:43:56.174580Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 26
2023-01-20T10:43:56.174649Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::26
2023-01-20T10:43:56.174662Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.174673Z  INFO evm_eth_compliance::statetest::runner: TX len : 19
2023-01-20T10:43:56.174682Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [111, 147, 192, 52, 171, 133, 194, 43, 155, 235, 44, 71, 65, 131, 48, 14, 172, 155, 82, 35, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([69, 131, 204, 221, 179, 65, 199, 98, 73, 40, 62, 85, 214, 176, 36, 150, 250, 184, 22, 95]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.178505Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11343631,
    events_root: None,
}
2023-01-20T10:43:56.178564Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 27
2023-01-20T10:43:56.178614Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::27
2023-01-20T10:43:56.178622Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.178630Z  INFO evm_eth_compliance::statetest::runner: TX len : 19
2023-01-20T10:43:56.178636Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [44, 252, 113, 215, 123, 82, 131, 51, 6, 230, 26, 244, 165, 168, 31, 151, 58, 102, 172, 70, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([81, 241, 105, 70, 35, 231, 218, 33, 101, 191, 237, 161, 1, 224, 12, 88, 37, 86, 193, 107]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.182835Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11445603,
    events_root: None,
}
2023-01-20T10:43:56.182949Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 28
2023-01-20T10:43:56.183017Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::28
2023-01-20T10:43:56.183029Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.183038Z  INFO evm_eth_compliance::statetest::runner: TX len : 13
2023-01-20T10:43:56.183047Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [50, 187, 163, 202, 176, 88, 230, 204, 108, 60, 107, 216, 168, 205, 165, 121, 46, 217, 34, 125, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([173, 69, 234, 11, 113, 222, 23, 14, 141, 254, 2, 0, 172, 141, 64, 31, 76, 189, 53, 221]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.187886Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11859173,
    events_root: None,
}
2023-01-20T10:43:56.188014Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 29
2023-01-20T10:43:56.188084Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::29
2023-01-20T10:43:56.188096Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.188107Z  INFO evm_eth_compliance::statetest::runner: TX len : 21
2023-01-20T10:43:56.188116Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [189, 148, 3, 19, 102, 83, 229, 180, 137, 10, 5, 193, 56, 103, 164, 14, 151, 57, 228, 176, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([123, 146, 155, 222, 229, 55, 80, 56, 39, 190, 248, 95, 176, 90, 235, 24, 130, 136, 28, 43]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.193023Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11241082,
    events_root: None,
}
2023-01-20T10:43:56.193142Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 30
2023-01-20T10:43:56.193211Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::30
2023-01-20T10:43:56.193222Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.193232Z  INFO evm_eth_compliance::statetest::runner: TX len : 22
2023-01-20T10:43:56.193241Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [109, 15, 74, 78, 78, 83, 123, 157, 78, 78, 158, 212, 21, 13, 29, 170, 145, 179, 154, 140, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([14, 92, 225, 123, 241, 53, 39, 34, 94, 147, 206, 76, 34, 22, 92, 23, 178, 0, 207, 187]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.197893Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12251148,
    events_root: None,
}
2023-01-20T10:43:56.197983Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 31
2023-01-20T10:43:56.198038Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::31
2023-01-20T10:43:56.198046Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.198054Z  INFO evm_eth_compliance::statetest::runner: TX len : 22
2023-01-20T10:43:56.198060Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [171, 72, 130, 111, 72, 60, 136, 48, 2, 37, 188, 83, 51, 94, 93, 30, 117, 152, 221, 234, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([19, 211, 136, 28, 116, 142, 24, 149, 26, 197, 120, 79, 254, 155, 86, 52, 22, 153, 82, 180]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.201999Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11260946,
    events_root: None,
}
2023-01-20T10:43:56.202075Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 32
2023-01-20T10:43:56.202125Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::32
2023-01-20T10:43:56.202134Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.202141Z  INFO evm_eth_compliance::statetest::runner: TX len : 22
2023-01-20T10:43:56.202147Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [24, 147, 167, 220, 213, 123, 169, 244, 143, 210, 87, 90, 99, 201, 1, 24, 28, 202, 255, 164, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([73, 32, 84, 24, 97, 22, 215, 89, 235, 130, 5, 49, 27, 52, 54, 141, 112, 8, 34, 1]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.205649Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11330058,
    events_root: None,
}
2023-01-20T10:43:56.205716Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 33
2023-01-20T10:43:56.205758Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::33
2023-01-20T10:43:56.205766Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.205773Z  INFO evm_eth_compliance::statetest::runner: TX len : 16
2023-01-20T10:43:56.205779Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [150, 254, 202, 0, 248, 124, 234, 95, 1, 6, 36, 104, 156, 38, 60, 83, 161, 27, 18, 203, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([30, 200, 89, 120, 93, 31, 177, 158, 220, 62, 143, 117, 32, 130, 8, 77, 176, 149, 68, 83]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.209479Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11325972,
    events_root: None,
}
2023-01-20T10:43:56.209553Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 34
2023-01-20T10:43:56.209601Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::34
2023-01-20T10:43:56.209609Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.209617Z  INFO evm_eth_compliance::statetest::runner: TX len : 17
2023-01-20T10:43:56.209623Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [232, 100, 64, 55, 156, 100, 104, 123, 237, 125, 69, 72, 5, 145, 8, 51, 228, 167, 34, 224, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([85, 73, 172, 47, 2, 233, 84, 197, 167, 3, 142, 2, 156, 38, 221, 36, 36, 26, 241, 253]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.212894Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10427590,
    events_root: None,
}
2023-01-20T10:43:56.212944Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 35
2023-01-20T10:43:56.212978Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::35
2023-01-20T10:43:56.212986Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.212994Z  INFO evm_eth_compliance::statetest::runner: TX len : 12
2023-01-20T10:43:56.213000Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [83, 138, 160, 182, 135, 4, 105, 94, 2, 240, 101, 96, 96, 251, 34, 24, 26, 101, 140, 82, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([0, 31, 18, 36, 234, 222, 200, 103, 149, 89, 8, 246, 140, 177, 92, 56, 18, 120, 242, 235]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.216526Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12276009,
    events_root: None,
}
2023-01-20T10:43:56.216580Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 36
2023-01-20T10:43:56.216610Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::36
2023-01-20T10:43:56.216617Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.216624Z  INFO evm_eth_compliance::statetest::runner: TX len : 13
2023-01-20T10:43:56.216630Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [9, 65, 108, 181, 174, 168, 201, 236, 244, 157, 208, 45, 99, 215, 92, 250, 240, 40, 163, 229, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([255, 33, 67, 106, 108, 165, 61, 177, 123, 246, 129, 116, 107, 248, 55, 11, 204, 92, 198, 140]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.220013Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11805459,
    events_root: None,
}
2023-01-20T10:43:56.220065Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 37
2023-01-20T10:43:56.220093Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::37
2023-01-20T10:43:56.220100Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.220107Z  INFO evm_eth_compliance::statetest::runner: TX len : 14
2023-01-20T10:43:56.220113Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [253, 78, 83, 198, 13, 81, 172, 238, 50, 105, 15, 68, 207, 144, 35, 175, 95, 180, 81, 122, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 64, 210, 78, 230, 195, 74, 76, 236, 40, 17, 14, 251, 95, 210, 114, 223, 39, 145, 47]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.223296Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10439063,
    events_root: None,
}
2023-01-20T10:43:56.223352Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 38
2023-01-20T10:43:56.223385Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::38
2023-01-20T10:43:56.223392Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.223399Z  INFO evm_eth_compliance::statetest::runner: TX len : 21
2023-01-20T10:43:56.223405Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [172, 110, 80, 189, 210, 228, 193, 167, 143, 24, 127, 109, 63, 234, 156, 212, 12, 135, 153, 230, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([68, 22, 34, 193, 75, 142, 227, 206, 86, 97, 115, 67, 101, 174, 23, 9, 189, 6, 63, 181]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.227297Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11261906,
    events_root: None,
}
2023-01-20T10:43:56.227367Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 39
2023-01-20T10:43:56.227413Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::39
2023-01-20T10:43:56.227421Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.227428Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T10:43:56.227434Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [160, 161, 205, 114, 209, 16, 154, 132, 15, 66, 248, 120, 252, 111, 61, 0, 73, 63, 238, 59, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([53, 255, 213, 192, 100, 77, 179, 253, 196, 93, 209, 10, 95, 195, 187, 190, 132, 159, 113, 247]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.231254Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11386902,
    events_root: None,
}
2023-01-20T10:43:56.231310Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 40
2023-01-20T10:43:56.231344Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::40
2023-01-20T10:43:56.231351Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.231359Z  INFO evm_eth_compliance::statetest::runner: TX len : 23
2023-01-20T10:43:56.231366Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [141, 178, 101, 21, 94, 208, 170, 52, 33, 240, 65, 176, 154, 181, 196, 250, 188, 152, 10, 146, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([133, 22, 115, 192, 108, 200, 122, 163, 50, 70, 32, 177, 79, 165, 117, 0, 68, 80, 148, 237]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.234720Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11239200,
    events_root: None,
}
2023-01-20T10:43:56.234771Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 41
2023-01-20T10:43:56.234801Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::41
2023-01-20T10:43:56.234807Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.234814Z  INFO evm_eth_compliance::statetest::runner: TX len : 25
2023-01-20T10:43:56.234820Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [242, 228, 96, 54, 241, 106, 222, 127, 136, 172, 215, 180, 149, 34, 69, 123, 193, 61, 232, 47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 118, 249, 232, 162, 47, 202, 110, 147, 179, 162, 196, 127, 76, 38, 197, 254, 226, 116, 25]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.238289Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12157580,
    events_root: None,
}
2023-01-20T10:43:56.238351Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 42
2023-01-20T10:43:56.238383Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::42
2023-01-20T10:43:56.238391Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.238398Z  INFO evm_eth_compliance::statetest::runner: TX len : 27
2023-01-20T10:43:56.238404Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [115, 137, 166, 84, 205, 1, 160, 254, 146, 79, 109, 161, 249, 34, 222, 71, 11, 18, 2, 26, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([93, 16, 194, 134, 236, 156, 66, 69, 215, 73, 158, 176, 199, 151, 104, 167, 104, 217, 242, 45]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.242091Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10447786,
    events_root: None,
}
2023-01-20T10:43:56.242171Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 43
2023-01-20T10:43:56.242218Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::43
2023-01-20T10:43:56.242226Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.242234Z  INFO evm_eth_compliance::statetest::runner: TX len : 34
2023-01-20T10:43:56.242240Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [160, 227, 223, 198, 203, 112, 188, 162, 229, 2, 135, 25, 249, 185, 189, 145, 109, 211, 197, 217, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([97, 20, 162, 25, 241, 99, 62, 62, 238, 184, 19, 89, 46, 231, 71, 37, 76, 120, 23, 169]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.245537Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10434732,
    events_root: None,
}
2023-01-20T10:43:56.245589Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 44
2023-01-20T10:43:56.245618Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::44
2023-01-20T10:43:56.245625Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.245632Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:43:56.245638Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [217, 2, 235, 96, 26, 116, 166, 162, 18, 109, 176, 194, 157, 202, 103, 25, 225, 41, 135, 154, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([246, 105, 84, 56, 255, 227, 13, 84, 13, 11, 224, 150, 6, 66, 109, 38, 133, 12, 18, 3]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.249108Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11257892,
    events_root: None,
}
2023-01-20T10:43:56.249174Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 45
2023-01-20T10:43:56.249211Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::45
2023-01-20T10:43:56.249218Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.249226Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:43:56.249232Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [10, 183, 77, 203, 146, 89, 167, 125, 52, 109, 64, 191, 94, 126, 184, 7, 253, 149, 129, 253, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([71, 85, 103, 172, 146, 131, 63, 188, 105, 157, 2, 79, 90, 252, 36, 180, 154, 212, 39, 248]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.252604Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11302501,
    events_root: None,
}
2023-01-20T10:43:56.252654Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 46
2023-01-20T10:43:56.252683Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::46
2023-01-20T10:43:56.252690Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.252697Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:43:56.252703Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [119, 36, 118, 109, 99, 114, 172, 254, 50, 155, 119, 164, 216, 75, 177, 119, 138, 134, 71, 114, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([142, 232, 164, 78, 145, 27, 180, 23, 232, 93, 146, 214, 81, 17, 121, 47, 130, 32, 173, 172]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.256607Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11862060,
    events_root: None,
}
2023-01-20T10:43:56.256697Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 47
2023-01-20T10:43:56.256746Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::47
2023-01-20T10:43:56.256755Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.256763Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T10:43:56.256769Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [244, 103, 204, 176, 48, 254, 142, 43, 159, 161, 24, 127, 212, 69, 230, 115, 47, 15, 228, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([73, 110, 175, 196, 139, 26, 95, 182, 220, 117, 224, 28, 224, 28, 191, 158, 210, 250, 193, 127]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.260299Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11348508,
    events_root: None,
}
2023-01-20T10:43:56.260351Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 48
2023-01-20T10:43:56.260382Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::48
2023-01-20T10:43:56.260389Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.260396Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T10:43:56.260402Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [70, 155, 30, 213, 210, 32, 142, 64, 146, 38, 126, 151, 70, 99, 30, 65, 76, 167, 56, 138, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([102, 4, 159, 103, 55, 6, 220, 77, 176, 138, 154, 32, 108, 212, 246, 214, 214, 254, 146, 11]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.263875Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12130821,
    events_root: None,
}
2023-01-20T10:43:56.263928Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 49
2023-01-20T10:43:56.263958Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::49
2023-01-20T10:43:56.263965Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.263972Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T10:43:56.263978Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [1, 85, 168, 254, 174, 228, 152, 243, 122, 73, 221, 30, 183, 141, 206, 168, 41, 24, 120, 211, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([128, 114, 28, 92, 72, 156, 139, 168, 197, 200, 166, 35, 207, 231, 205, 27, 28, 92, 97, 176]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.267410Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11797155,
    events_root: None,
}
2023-01-20T10:43:56.267463Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 50
2023-01-20T10:43:56.267492Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::50
2023-01-20T10:43:56.267500Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.267507Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T10:43:56.267513Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [224, 219, 228, 3, 111, 154, 145, 183, 183, 143, 82, 80, 20, 122, 196, 150, 50, 64, 135, 178, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([193, 123, 98, 16, 65, 140, 197, 189, 32, 0, 172, 183, 48, 226, 253, 71, 65, 120, 212, 199]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.270920Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12093288,
    events_root: None,
}
2023-01-20T10:43:56.270978Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 51
2023-01-20T10:43:56.271010Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::51
2023-01-20T10:43:56.271017Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.271024Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T10:43:56.271030Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [2, 94, 155, 31, 12, 19, 195, 250, 240, 202, 98, 21, 238, 28, 111, 175, 34, 187, 58, 185, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([96, 173, 161, 250, 144, 43, 25, 188, 114, 55, 151, 97, 99, 70, 217, 20, 93, 225, 254, 117]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.274972Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11328371,
    events_root: None,
}
2023-01-20T10:43:56.275052Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 52
2023-01-20T10:43:56.275099Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::52
2023-01-20T10:43:56.275107Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.275114Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T10:43:56.275121Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [153, 203, 223, 213, 200, 33, 217, 40, 46, 123, 243, 12, 219, 152, 69, 199, 234, 173, 195, 163, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([106, 70, 189, 14, 102, 233, 163, 80, 251, 83, 92, 59, 39, 192, 134, 90, 171, 213, 150, 87]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.278703Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12197182,
    events_root: None,
}
2023-01-20T10:43:56.278756Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 53
2023-01-20T10:43:56.278784Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::53
2023-01-20T10:43:56.278792Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.278799Z  INFO evm_eth_compliance::statetest::runner: TX len : 24
2023-01-20T10:43:56.278804Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [237, 235, 128, 74, 153, 80, 174, 45, 143, 108, 221, 91, 210, 25, 110, 245, 205, 251, 186, 92, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([24, 42, 251, 77, 22, 15, 176, 255, 32, 254, 220, 107, 21, 224, 233, 137, 114, 181, 18, 37]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.282214Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11281990,
    events_root: None,
}
2023-01-20T10:43:56.282273Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 54
2023-01-20T10:43:56.282305Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::54
2023-01-20T10:43:56.282312Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.282319Z  INFO evm_eth_compliance::statetest::runner: TX len : 24
2023-01-20T10:43:56.282325Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [91, 179, 216, 94, 136, 208, 17, 248, 49, 181, 201, 49, 227, 61, 204, 154, 69, 142, 249, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([210, 82, 192, 2, 89, 118, 236, 228, 172, 117, 53, 238, 120, 207, 64, 37, 208, 224, 40, 106]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.285597Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10998135,
    events_root: None,
}
2023-01-20T10:43:56.285652Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 55
2023-01-20T10:43:56.285680Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::55
2023-01-20T10:43:56.285688Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.285695Z  INFO evm_eth_compliance::statetest::runner: TX len : 24
2023-01-20T10:43:56.285701Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [149, 87, 79, 178, 82, 177, 128, 37, 238, 135, 126, 144, 188, 145, 178, 114, 113, 107, 130, 61, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([23, 227, 125, 105, 35, 40, 210, 157, 192, 139, 127, 9, 206, 66, 114, 214, 66, 185, 242, 11]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.288968Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11266469,
    events_root: None,
}
2023-01-20T10:43:56.289020Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 56
2023-01-20T10:43:56.289049Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::56
2023-01-20T10:43:56.289056Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.289065Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T10:43:56.289074Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [49, 117, 82, 189, 69, 59, 166, 234, 22, 57, 99, 215, 100, 96, 66, 162, 243, 242, 235, 193, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([124, 172, 180, 79, 232, 154, 153, 154, 118, 107, 46, 154, 5, 214, 190, 36, 199, 162, 18, 50]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.293232Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12253968,
    events_root: None,
}
2023-01-20T10:43:56.293303Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 57
2023-01-20T10:43:56.293350Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::57
2023-01-20T10:43:56.293358Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.293365Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.293371Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [147, 168, 217, 142, 128, 210, 88, 67, 61, 231, 153, 199, 219, 150, 227, 226, 182, 6, 137, 228, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([112, 29, 15, 64, 178, 146, 53, 249, 144, 128, 18, 166, 211, 1, 231, 201, 176, 236, 30, 194]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.296864Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12355405,
    events_root: None,
}
2023-01-20T10:43:56.296916Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 58
2023-01-20T10:43:56.296945Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::58
2023-01-20T10:43:56.296958Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.296965Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.296971Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [232, 233, 247, 141, 122, 226, 136, 190, 224, 57, 78, 221, 191, 78, 123, 46, 150, 37, 126, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([85, 39, 46, 125, 78, 54, 16, 212, 174, 203, 4, 11, 164, 87, 253, 39, 189, 242, 193, 95]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.300654Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11806762,
    events_root: None,
}
2023-01-20T10:43:56.300720Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 59
2023-01-20T10:43:56.300760Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::59
2023-01-20T10:43:56.300768Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.300775Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.300781Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [225, 147, 142, 249, 21, 1, 225, 240, 204, 6, 163, 127, 107, 83, 47, 101, 27, 145, 71, 149, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([75, 13, 168, 18, 182, 152, 47, 144, 239, 190, 47, 225, 22, 134, 57, 164, 95, 102, 191, 78]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.304126Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11256489,
    events_root: None,
}
2023-01-20T10:43:56.304184Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 60
2023-01-20T10:43:56.304217Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::60
2023-01-20T10:43:56.304224Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.304231Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.304238Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [84, 170, 107, 148, 89, 243, 214, 2, 89, 156, 137, 157, 61, 205, 141, 255, 20, 98, 34, 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([35, 244, 110, 128, 191, 180, 24, 192, 218, 210, 177, 9, 155, 212, 117, 40, 49, 85, 55, 39]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.307528Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10959212,
    events_root: None,
}
2023-01-20T10:43:56.307579Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 61
2023-01-20T10:43:56.307608Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::61
2023-01-20T10:43:56.307615Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.307622Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.307628Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [152, 184, 16, 205, 209, 28, 122, 144, 226, 5, 247, 91, 104, 147, 21, 173, 100, 59, 216, 207, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([86, 152, 122, 252, 253, 199, 136, 213, 114, 61, 38, 211, 1, 47, 49, 33, 56, 151, 163, 20]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.311337Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11270545,
    events_root: None,
}
2023-01-20T10:43:56.311420Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 62
2023-01-20T10:43:56.311465Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::62
2023-01-20T10:43:56.311473Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.311480Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.311486Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [70, 203, 99, 14, 15, 22, 7, 158, 70, 153, 6, 225, 107, 32, 231, 248, 210, 51, 250, 140, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([13, 69, 82, 46, 142, 62, 215, 188, 83, 88, 41, 62, 103, 88, 24, 255, 61, 193, 168, 241]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.315159Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12191210,
    events_root: None,
}
2023-01-20T10:43:56.315215Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 63
2023-01-20T10:43:56.315251Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::63
2023-01-20T10:43:56.315258Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.315265Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.315271Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [198, 85, 121, 248, 218, 210, 132, 223, 4, 61, 248, 205, 124, 185, 108, 207, 163, 46, 29, 85, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([156, 175, 176, 156, 215, 103, 7, 203, 17, 252, 18, 116, 52, 61, 38, 232, 156, 66, 198, 248]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.318702Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11778713,
    events_root: None,
}
2023-01-20T10:43:56.318754Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 64
2023-01-20T10:43:56.318784Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::64
2023-01-20T10:43:56.318791Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.318798Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.318804Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [91, 209, 207, 133, 120, 73, 108, 115, 60, 255, 184, 199, 14, 108, 14, 48, 4, 114, 168, 80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([88, 145, 29, 245, 240, 11, 87, 174, 247, 17, 7, 95, 7, 35, 177, 53, 116, 191, 242, 202]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.322099Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10945294,
    events_root: None,
}
2023-01-20T10:43:56.322156Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 65
2023-01-20T10:43:56.322188Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::65
2023-01-20T10:43:56.322196Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.322203Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.322209Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [22, 195, 24, 20, 182, 24, 196, 48, 84, 8, 185, 138, 39, 96, 124, 26, 100, 209, 28, 198, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([243, 183, 185, 31, 121, 210, 182, 175, 155, 168, 24, 242, 13, 143, 97, 234, 106, 120, 71, 235]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.326145Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11473995,
    events_root: None,
}
2023-01-20T10:43:56.326228Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 66
2023-01-20T10:43:56.326274Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::66
2023-01-20T10:43:56.326282Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.326289Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.326295Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [171, 46, 201, 27, 125, 45, 33, 138, 154, 109, 158, 215, 115, 138, 116, 177, 85, 60, 142, 98, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([164, 153, 119, 134, 164, 138, 62, 179, 133, 14, 22, 162, 37, 191, 99, 7, 147, 197, 26, 119]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.329558Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10443642,
    events_root: None,
}
2023-01-20T10:43:56.329607Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 67
2023-01-20T10:43:56.329636Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::67
2023-01-20T10:43:56.329643Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.329650Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.329656Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [91, 49, 235, 33, 81, 238, 227, 53, 190, 54, 111, 48, 42, 234, 140, 205, 146, 145, 185, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([154, 196, 10, 175, 154, 130, 130, 90, 125, 225, 212, 183, 141, 220, 233, 243, 138, 222, 97, 65]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.333271Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11960673,
    events_root: None,
}
2023-01-20T10:43:56.333328Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 68
2023-01-20T10:43:56.333362Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::68
2023-01-20T10:43:56.333369Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.333376Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.333382Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [137, 249, 78, 7, 10, 166, 66, 151, 247, 228, 158, 30, 192, 86, 52, 239, 145, 124, 244, 87, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([178, 88, 42, 217, 4, 79, 184, 115, 249, 172, 73, 105, 218, 48, 15, 242, 121, 222, 53, 27]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.336807Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12174574,
    events_root: None,
}
2023-01-20T10:43:56.336858Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 69
2023-01-20T10:43:56.336886Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::69
2023-01-20T10:43:56.336893Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.336900Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.336906Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [232, 82, 236, 87, 77, 224, 164, 71, 55, 221, 164, 109, 209, 199, 239, 142, 233, 254, 129, 58, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([130, 111, 124, 187, 231, 26, 176, 66, 95, 237, 183, 47, 142, 239, 89, 90, 215, 105, 49, 252]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.340986Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11463178,
    events_root: None,
}
2023-01-20T10:43:56.341073Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 70
2023-01-20T10:43:56.341123Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::70
2023-01-20T10:43:56.341131Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.341138Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.341144Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [202, 114, 220, 6, 225, 48, 123, 129, 149, 111, 88, 62, 11, 8, 71, 41, 199, 92, 107, 130, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([195, 158, 219, 255, 25, 234, 218, 128, 119, 37, 161, 32, 230, 193, 181, 40, 70, 202, 181, 43]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.344680Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12201756,
    events_root: None,
}
2023-01-20T10:43:56.344733Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 71
2023-01-20T10:43:56.344762Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::71
2023-01-20T10:43:56.344770Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.344776Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.344782Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [5, 174, 168, 149, 247, 77, 20, 251, 118, 17, 150, 36, 13, 13, 188, 11, 251, 73, 201, 204, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([142, 78, 82, 158, 237, 190, 248, 244, 216, 111, 39, 24, 57, 18, 16, 78, 127, 120, 252, 63]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.348124Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10962332,
    events_root: None,
}
2023-01-20T10:43:56.348178Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 72
2023-01-20T10:43:56.348209Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::72
2023-01-20T10:43:56.348216Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.348223Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.348229Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [195, 93, 214, 80, 87, 12, 186, 19, 215, 185, 184, 91, 208, 99, 146, 17, 224, 154, 161, 81, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([133, 234, 42, 204, 128, 110, 48, 71, 216, 90, 90, 42, 65, 111, 117, 26, 57, 162, 184, 170]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.351529Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11335058,
    events_root: None,
}
2023-01-20T10:43:56.351581Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 73
2023-01-20T10:43:56.351611Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::73
2023-01-20T10:43:56.351618Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.351625Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.351631Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [126, 40, 77, 36, 114, 251, 109, 144, 246, 158, 162, 112, 161, 193, 77, 84, 228, 56, 71, 237, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([59, 5, 148, 33, 112, 238, 179, 79, 138, 16, 189, 109, 254, 117, 218, 157, 249, 185, 164, 15]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.354842Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10446818,
    events_root: None,
}
2023-01-20T10:43:56.354920Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 74
2023-01-20T10:43:56.354964Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::74
2023-01-20T10:43:56.354976Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.354986Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.354995Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [110, 63, 159, 152, 136, 74, 53, 120, 250, 65, 71, 221, 16, 131, 107, 103, 112, 79, 48, 213, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([206, 79, 82, 121, 60, 54, 151, 141, 147, 67, 237, 195, 220, 113, 163, 55, 30, 86, 157, 2]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.359019Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12138032,
    events_root: None,
}
2023-01-20T10:43:56.359082Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 75
2023-01-20T10:43:56.359125Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::75
2023-01-20T10:43:56.359133Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.359141Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.359147Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [12, 22, 76, 61, 156, 115, 134, 232, 191, 160, 235, 240, 134, 77, 241, 54, 157, 141, 208, 82, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([158, 87, 16, 34, 106, 159, 135, 162, 41, 45, 26, 59, 16, 104, 74, 241, 23, 233, 82, 114]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.362426Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10952532,
    events_root: None,
}
2023-01-20T10:43:56.362477Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 76
2023-01-20T10:43:56.362506Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::76
2023-01-20T10:43:56.362513Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.362520Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.362526Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [115, 192, 233, 29, 25, 34, 109, 40, 225, 76, 138, 209, 218, 188, 81, 148, 174, 120, 213, 147, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([143, 38, 219, 127, 27, 65, 48, 153, 123, 44, 181, 166, 164, 41, 17, 206, 203, 19, 247, 217]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.365971Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11406329,
    events_root: None,
}
2023-01-20T10:43:56.366026Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 77
2023-01-20T10:43:56.366057Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::77
2023-01-20T10:43:56.366064Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.366072Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.366078Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [229, 95, 67, 168, 35, 152, 163, 74, 77, 144, 65, 246, 253, 34, 117, 77, 74, 46, 5, 178, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([71, 180, 242, 55, 64, 247, 150, 100, 76, 19, 196, 103, 103, 3, 197, 78, 87, 151, 251, 189]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.369334Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10950901,
    events_root: None,
}
2023-01-20T10:43:56.369385Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 78
2023-01-20T10:43:56.369413Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::78
2023-01-20T10:43:56.369420Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.369428Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.369434Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [194, 108, 72, 251, 143, 149, 26, 170, 197, 112, 177, 50, 138, 146, 28, 197, 183, 98, 139, 113, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([113, 48, 13, 220, 158, 134, 199, 50, 90, 148, 165, 244, 89, 183, 71, 40, 18, 240, 77, 201]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.373008Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10974671,
    events_root: None,
}
2023-01-20T10:43:56.373117Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 79
2023-01-20T10:43:56.373176Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::79
2023-01-20T10:43:56.373188Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.373198Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.373207Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [22, 90, 10, 194, 206, 121, 44, 90, 93, 112, 240, 24, 108, 22, 52, 27, 189, 220, 54, 243, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([176, 152, 11, 44, 71, 253, 75, 55, 159, 225, 50, 221, 76, 9, 209, 191, 96, 6, 255, 54]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.376784Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11246577,
    events_root: None,
}
2023-01-20T10:43:56.376837Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 80
2023-01-20T10:43:56.376871Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::80
2023-01-20T10:43:56.376879Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.376886Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.376892Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [147, 25, 210, 96, 224, 62, 188, 65, 48, 205, 108, 162, 61, 12, 172, 202, 168, 106, 240, 180, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([7, 37, 114, 46, 140, 87, 23, 200, 167, 18, 242, 69, 114, 79, 92, 170, 102, 218, 79, 132]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.380170Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11331500,
    events_root: None,
}
2023-01-20T10:43:56.380219Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 81
2023-01-20T10:43:56.380247Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::81
2023-01-20T10:43:56.380254Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.380261Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.380267Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [36, 246, 98, 174, 11, 97, 157, 246, 98, 114, 78, 47, 95, 48, 217, 89, 184, 83, 32, 233, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([5, 55, 88, 33, 212, 122, 183, 159, 130, 207, 189, 179, 8, 203, 172, 41, 168, 224, 189, 123]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.383631Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11361033,
    events_root: None,
}
2023-01-20T10:43:56.383684Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 82
2023-01-20T10:43:56.383716Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::82
2023-01-20T10:43:56.383723Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.383730Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.383736Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [198, 41, 226, 210, 163, 252, 4, 215, 255, 2, 97, 41, 95, 144, 75, 26, 169, 246, 133, 126, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([18, 117, 255, 191, 219, 252, 31, 136, 170, 188, 255, 168, 135, 127, 17, 28, 127, 240, 239, 99]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.387167Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11268283,
    events_root: None,
}
2023-01-20T10:43:56.387225Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 83
2023-01-20T10:43:56.387259Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::83
2023-01-20T10:43:56.387267Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.387274Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.387280Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [22, 56, 20, 57, 114, 161, 45, 156, 73, 26, 227, 247, 208, 61, 204, 64, 210, 191, 99, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([30, 98, 133, 230, 13, 118, 168, 210, 40, 88, 107, 18, 156, 25, 222, 231, 107, 21, 56, 124]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.390951Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10430700,
    events_root: None,
}
2023-01-20T10:43:56.391044Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 84
2023-01-20T10:43:56.391101Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::84
2023-01-20T10:43:56.391109Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.391117Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.391123Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [216, 133, 110, 103, 222, 62, 58, 10, 104, 125, 178, 191, 77, 199, 70, 148, 234, 205, 9, 49, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([13, 161, 243, 145, 198, 25, 141, 116, 134, 4, 159, 133, 150, 2, 214, 237, 252, 186, 30, 68]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.394737Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11866763,
    events_root: None,
}
2023-01-20T10:43:56.394786Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 85
2023-01-20T10:43:56.394817Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::85
2023-01-20T10:43:56.394824Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.394831Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.394837Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [177, 175, 155, 93, 59, 59, 80, 12, 170, 102, 147, 61, 73, 236, 109, 9, 115, 131, 177, 74, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([205, 108, 210, 93, 183, 235, 206, 39, 133, 71, 129, 213, 91, 209, 131, 18, 51, 98, 227, 220]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.398182Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11286582,
    events_root: None,
}
2023-01-20T10:43:56.398230Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 86
2023-01-20T10:43:56.398262Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::86
2023-01-20T10:43:56.398269Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.398275Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.398281Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [113, 15, 176, 148, 119, 6, 210, 23, 199, 232, 3, 245, 148, 171, 98, 179, 33, 160, 29, 213, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([99, 86, 199, 194, 253, 189, 25, 149, 195, 48, 53, 196, 184, 159, 163, 70, 2, 209, 99, 142]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.401765Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12186187,
    events_root: None,
}
2023-01-20T10:43:56.401814Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 87
2023-01-20T10:43:56.401844Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::87
2023-01-20T10:43:56.401851Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.401858Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.401864Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [9, 230, 50, 242, 189, 87, 121, 201, 246, 213, 58, 244, 155, 125, 172, 121, 65, 172, 131, 139, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([66, 0, 200, 220, 45, 175, 106, 113, 217, 136, 110, 243, 210, 195, 244, 186, 199, 71, 104, 194]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.405191Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11274328,
    events_root: None,
}
2023-01-20T10:43:56.405244Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 88
2023-01-20T10:43:56.405276Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::88
2023-01-20T10:43:56.405283Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.405290Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.405296Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [123, 112, 93, 173, 235, 191, 106, 219, 66, 129, 76, 183, 30, 185, 149, 11, 250, 239, 168, 60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([195, 240, 43, 58, 38, 52, 20, 234, 159, 49, 76, 86, 139, 219, 17, 145, 197, 0, 165, 175]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.409164Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11265352,
    events_root: None,
}
2023-01-20T10:43:56.409230Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 89
2023-01-20T10:43:56.409277Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::89
2023-01-20T10:43:56.409286Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.409293Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.409299Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [238, 145, 153, 163, 130, 148, 48, 193, 239, 229, 89, 183, 164, 50, 160, 26, 183, 110, 126, 38, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([24, 168, 191, 225, 219, 171, 97, 126, 201, 174, 154, 100, 189, 198, 198, 228, 73, 208, 12, 186]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.412773Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12121638,
    events_root: None,
}
2023-01-20T10:43:56.412821Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 90
2023-01-20T10:43:56.412850Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::90
2023-01-20T10:43:56.412856Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.412863Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.412869Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [97, 33, 71, 52, 250, 42, 157, 230, 25, 84, 23, 116, 140, 202, 190, 140, 8, 153, 76, 242, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([39, 102, 217, 172, 144, 100, 249, 162, 149, 197, 79, 161, 69, 86, 150, 82, 66, 185, 188, 69]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.416255Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11271857,
    events_root: None,
}
2023-01-20T10:43:56.416304Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 91
2023-01-20T10:43:56.416336Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::91
2023-01-20T10:43:56.416343Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.416350Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.416356Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 238, 54, 254, 166, 176, 174, 142, 190, 238, 205, 130, 78, 10, 44, 13, 60, 84, 187, 97, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([18, 244, 73, 243, 226, 9, 13, 67, 73, 181, 124, 65, 111, 153, 172, 123, 233, 6, 28, 213]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.419489Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10434476,
    events_root: None,
}
2023-01-20T10:43:56.419538Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 92
2023-01-20T10:43:56.419566Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::92
2023-01-20T10:43:56.419573Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.419580Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.419586Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [249, 11, 146, 49, 46, 108, 91, 215, 147, 187, 188, 39, 119, 228, 255, 189, 242, 187, 151, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([23, 12, 100, 122, 207, 3, 210, 37, 58, 58, 80, 153, 119, 9, 18, 127, 105, 225, 33, 245]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.422898Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10958801,
    events_root: None,
}
2023-01-20T10:43:56.422958Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 93
2023-01-20T10:43:56.422992Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::93
2023-01-20T10:43:56.422999Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.423006Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.423012Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [77, 66, 251, 33, 124, 143, 24, 230, 18, 146, 144, 147, 205, 113, 98, 208, 71, 158, 65, 127, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([107, 80, 139, 145, 111, 121, 190, 39, 37, 7, 148, 111, 215, 89, 66, 207, 129, 52, 187, 232]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.427504Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11852151,
    events_root: None,
}
2023-01-20T10:43:56.427605Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 94
2023-01-20T10:43:56.427660Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::94
2023-01-20T10:43:56.427668Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.427675Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.427681Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [60, 99, 4, 233, 99, 215, 37, 222, 209, 198, 94, 98, 81, 77, 105, 79, 120, 146, 246, 197, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([168, 174, 148, 121, 60, 81, 86, 22, 174, 80, 209, 105, 120, 93, 54, 174, 180, 137, 158, 61]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.431596Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10487848,
    events_root: None,
}
2023-01-20T10:43:56.431677Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 95
2023-01-20T10:43:56.431728Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::95
2023-01-20T10:43:56.431736Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.431744Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.431750Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [103, 198, 241, 252, 162, 196, 175, 133, 235, 6, 61, 40, 235, 215, 121, 247, 206, 104, 161, 183, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([230, 95, 117, 126, 35, 169, 121, 4, 139, 234, 252, 240, 104, 239, 4, 238, 66, 179, 171, 16]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.435455Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10967689,
    events_root: None,
}
2023-01-20T10:43:56.435521Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 96
2023-01-20T10:43:56.435566Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::96
2023-01-20T10:43:56.435574Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.435581Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.435588Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [93, 140, 215, 235, 0, 105, 36, 89, 45, 92, 70, 183, 246, 182, 233, 172, 80, 17, 221, 183, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([142, 85, 107, 233, 146, 124, 123, 145, 122, 141, 124, 107, 1, 239, 223, 2, 188, 212, 188, 209]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.440276Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11963220,
    events_root: None,
}
2023-01-20T10:43:56.440373Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 97
2023-01-20T10:43:56.440428Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::97
2023-01-20T10:43:56.440435Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.440443Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.440449Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [15, 208, 1, 127, 29, 250, 4, 0, 119, 95, 41, 119, 30, 151, 162, 199, 59, 73, 248, 169, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([199, 73, 3, 166, 145, 28, 224, 147, 17, 199, 39, 23, 230, 43, 43, 251, 240, 147, 225, 109]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.443890Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10469918,
    events_root: None,
}
2023-01-20T10:43:56.443954Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 98
2023-01-20T10:43:56.444000Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::98
2023-01-20T10:43:56.444008Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.444016Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.444022Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [178, 194, 225, 139, 87, 53, 53, 223, 43, 128, 235, 11, 113, 52, 78, 4, 55, 221, 32, 194, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([35, 155, 192, 163, 237, 163, 58, 216, 91, 139, 250, 108, 109, 93, 15, 190, 28, 1, 27, 109]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.447496Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10976798,
    events_root: None,
}
2023-01-20T10:43:56.447556Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 99
2023-01-20T10:43:56.447595Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::99
2023-01-20T10:43:56.447603Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.447611Z  INFO evm_eth_compliance::statetest::runner: TX len : 77
2023-01-20T10:43:56.447617Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [41, 37, 129, 189, 210, 233, 35, 219, 216, 53, 125, 192, 74, 142, 244, 189, 128, 251, 188, 97, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([183, 229, 7, 154, 250, 45, 213, 171, 171, 92, 2, 92, 4, 234, 224, 185, 39, 216, 44, 72]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.451028Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11006069,
    events_root: None,
}
2023-01-20T10:43:56.451080Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 100
2023-01-20T10:43:56.451111Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::100
2023-01-20T10:43:56.451118Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.451126Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.451131Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [55, 87, 140, 243, 198, 127, 29, 210, 128, 235, 144, 247, 229, 94, 116, 178, 82, 203, 160, 156, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([231, 82, 174, 253, 177, 225, 29, 91, 156, 177, 36, 148, 188, 84, 42, 128, 132, 213, 34, 2]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.454608Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11337073,
    events_root: None,
}
2023-01-20T10:43:56.454706Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 101
2023-01-20T10:43:56.454759Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::101
2023-01-20T10:43:56.454767Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.454775Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.454781Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [202, 139, 52, 209, 139, 215, 144, 238, 230, 154, 182, 49, 141, 20, 66, 43, 186, 82, 254, 142, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([19, 66, 77, 101, 68, 180, 68, 190, 252, 111, 171, 10, 179, 234, 114, 7, 202, 228, 170, 41]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.458502Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11338784,
    events_root: None,
}
2023-01-20T10:43:56.458567Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 102
2023-01-20T10:43:56.458613Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::102
2023-01-20T10:43:56.458621Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.458628Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.458634Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [201, 103, 51, 239, 167, 225, 199, 142, 5, 157, 212, 255, 164, 97, 38, 144, 122, 2, 119, 117, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([62, 195, 130, 148, 111, 186, 93, 100, 124, 36, 163, 9, 93, 54, 115, 136, 128, 59, 184, 144]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.462130Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11460311,
    events_root: None,
}
2023-01-20T10:43:56.462184Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 103
2023-01-20T10:43:56.462214Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::103
2023-01-20T10:43:56.462221Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.462228Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.462234Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [160, 148, 151, 92, 159, 111, 56, 136, 115, 21, 148, 255, 166, 194, 162, 28, 169, 108, 152, 42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([84, 15, 54, 98, 68, 195, 154, 180, 8, 228, 151, 4, 35, 63, 50, 10, 124, 25, 44, 169]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.465694Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12120687,
    events_root: None,
}
2023-01-20T10:43:56.465787Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 104
2023-01-20T10:43:56.465823Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::104
2023-01-20T10:43:56.465830Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.465837Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.465843Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [15, 90, 142, 148, 65, 110, 28, 50, 245, 19, 181, 34, 205, 143, 224, 127, 76, 149, 143, 86, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([125, 248, 76, 91, 210, 9, 22, 232, 160, 51, 131, 136, 199, 114, 246, 64, 192, 211, 30, 70]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.469485Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11778140,
    events_root: None,
}
2023-01-20T10:43:56.469559Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 105
2023-01-20T10:43:56.469605Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::105
2023-01-20T10:43:56.469612Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.469619Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.469625Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [121, 255, 157, 109, 102, 110, 154, 165, 45, 218, 150, 30, 41, 85, 148, 4, 167, 241, 51, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([198, 171, 228, 199, 80, 50, 166, 211, 19, 170, 168, 119, 216, 234, 17, 127, 176, 84, 226, 235]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.473356Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10436375,
    events_root: None,
}
2023-01-20T10:43:56.473441Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 106
2023-01-20T10:43:56.473492Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::106
2023-01-20T10:43:56.473500Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.473507Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.473513Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [48, 182, 204, 128, 36, 107, 152, 209, 168, 204, 127, 113, 101, 99, 14, 191, 51, 191, 118, 216, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([148, 129, 233, 81, 55, 152, 116, 26, 41, 97, 44, 230, 139, 226, 18, 157, 242, 146, 245, 173]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.478047Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10964165,
    events_root: None,
}
2023-01-20T10:43:56.478155Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 107
2023-01-20T10:43:56.478227Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::107
2023-01-20T10:43:56.478249Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.478267Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.478283Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [167, 150, 190, 255, 235, 125, 108, 142, 201, 135, 17, 153, 79, 225, 80, 224, 192, 126, 81, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([55, 108, 200, 127, 204, 126, 216, 57, 64, 255, 231, 138, 165, 244, 239, 82, 12, 212, 49, 69]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.482418Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10439159,
    events_root: None,
}
2023-01-20T10:43:56.482506Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 108
2023-01-20T10:43:56.482557Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::108
2023-01-20T10:43:56.482567Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.482574Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.482580Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [24, 227, 69, 73, 70, 176, 240, 70, 23, 122, 181, 4, 181, 83, 105, 41, 117, 220, 2, 235, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([156, 120, 28, 151, 250, 120, 211, 218, 83, 25, 104, 128, 118, 118, 198, 138, 128, 162, 186, 111]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.486216Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11786346,
    events_root: None,
}
2023-01-20T10:43:56.486277Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 109
2023-01-20T10:43:56.486319Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::109
2023-01-20T10:43:56.486326Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.486333Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.486339Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [249, 69, 146, 156, 72, 197, 139, 88, 45, 77, 170, 213, 25, 48, 42, 10, 223, 154, 234, 86, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([37, 244, 135, 149, 209, 48, 2, 48, 112, 93, 116, 195, 45, 127, 234, 210, 245, 69, 157, 123]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.490247Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11792532,
    events_root: None,
}
2023-01-20T10:43:56.490345Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 110
2023-01-20T10:43:56.490400Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::110
2023-01-20T10:43:56.490408Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.490415Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.490422Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [225, 90, 149, 111, 185, 110, 200, 98, 48, 198, 101, 117, 27, 45, 58, 34, 24, 36, 39, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([8, 211, 21, 37, 7, 193, 253, 71, 53, 119, 215, 166, 217, 169, 134, 101, 7, 137, 60, 28]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.493949Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11333670,
    events_root: None,
}
2023-01-20T10:43:56.494001Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 111
2023-01-20T10:43:56.494034Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::111
2023-01-20T10:43:56.494042Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.494049Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.494055Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [127, 134, 45, 59, 190, 243, 229, 67, 70, 53, 42, 174, 163, 71, 217, 109, 183, 128, 108, 207, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([219, 166, 113, 75, 240, 46, 112, 28, 111, 120, 182, 148, 54, 63, 216, 22, 48, 233, 125, 168]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.497351Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10436577,
    events_root: None,
}
2023-01-20T10:43:56.497432Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 112
2023-01-20T10:43:56.497476Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::112
2023-01-20T10:43:56.497484Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.497493Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-20T10:43:56.497501Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [183, 254, 80, 239, 187, 13, 105, 83, 46, 207, 29, 76, 77, 1, 77, 20, 105, 85, 77, 226, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([122, 122, 241, 136, 229, 140, 23, 4, 235, 127, 104, 160, 232, 114, 95, 196, 76, 245, 88, 44]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.501235Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12191439,
    events_root: None,
}
2023-01-20T10:43:56.501300Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 113
2023-01-20T10:43:56.501343Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::113
2023-01-20T10:43:56.501353Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.501362Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:43:56.501370Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [227, 160, 32, 150, 1, 112, 0, 147, 34, 149, 73, 62, 170, 161, 34, 33, 85, 184, 79, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([33, 151, 159, 169, 91, 31, 128, 118, 117, 221, 225, 59, 200, 115, 27, 244, 198, 24, 173, 250]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.504844Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10995758,
    events_root: None,
}
2023-01-20T10:43:56.504922Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 114
2023-01-20T10:43:56.504988Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::114
2023-01-20T10:43:56.504998Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.505005Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:43:56.505011Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [43, 7, 148, 50, 232, 79, 232, 28, 38, 11, 18, 137, 51, 181, 93, 173, 137, 246, 11, 47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([217, 247, 90, 136, 53, 167, 109, 51, 167, 81, 151, 124, 214, 93, 64, 204, 217, 140, 172, 97]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.509140Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12208206,
    events_root: None,
}
2023-01-20T10:43:56.509211Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 115
2023-01-20T10:43:56.509260Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::115
2023-01-20T10:43:56.509268Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.509275Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T10:43:56.509281Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [244, 184, 220, 224, 244, 210, 172, 243, 53, 103, 85, 54, 234, 131, 4, 15, 198, 214, 82, 25, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([144, 163, 192, 51, 168, 218, 210, 154, 18, 171, 7, 219, 243, 129, 45, 148, 127, 235, 77, 15]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.512587Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10971596,
    events_root: None,
}
2023-01-20T10:43:56.512638Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 116
2023-01-20T10:43:56.512666Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::116
2023-01-20T10:43:56.512674Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.512681Z  INFO evm_eth_compliance::statetest::runner: TX len : 33
2023-01-20T10:43:56.512686Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [251, 10, 210, 26, 22, 252, 193, 56, 238, 242, 66, 86, 117, 146, 223, 227, 53, 206, 203, 163, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([147, 165, 62, 204, 7, 186, 144, 170, 24, 129, 12, 92, 152, 8, 83, 97, 135, 63, 179, 251]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.515911Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10488856,
    events_root: None,
}
2023-01-20T10:43:56.515964Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 117
2023-01-20T10:43:56.515998Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::117
2023-01-20T10:43:56.516006Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.516015Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:43:56.516023Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [170, 57, 93, 241, 137, 207, 64, 115, 111, 184, 13, 80, 59, 189, 101, 231, 111, 96, 205, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([169, 15, 227, 1, 108, 110, 139, 200, 99, 79, 241, 254, 65, 145, 128, 13, 72, 50, 175, 124]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.519459Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11274658,
    events_root: None,
}
2023-01-20T10:43:56.519509Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 118
2023-01-20T10:43:56.519537Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::118
2023-01-20T10:43:56.519544Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.519551Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:43:56.519557Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [221, 146, 54, 59, 207, 10, 23, 244, 255, 246, 75, 252, 5, 104, 120, 7, 253, 105, 114, 154, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([19, 196, 218, 186, 159, 61, 236, 144, 30, 19, 88, 161, 234, 84, 181, 227, 203, 208, 104, 201]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.522942Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10957949,
    events_root: None,
}
2023-01-20T10:43:56.523016Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 119
2023-01-20T10:43:56.523057Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::119
2023-01-20T10:43:56.523066Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.523076Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:43:56.523083Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [25, 140, 212, 162, 217, 159, 175, 165, 143, 76, 214, 92, 248, 62, 108, 154, 35, 252, 76, 152, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([6, 240, 239, 46, 219, 112, 198, 33, 58, 255, 180, 239, 116, 44, 97, 235, 137, 78, 199, 54]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.526748Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11342578,
    events_root: None,
}
2023-01-20T10:43:56.526813Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 120
2023-01-20T10:43:56.526855Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::120
2023-01-20T10:43:56.526864Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.526873Z  INFO evm_eth_compliance::statetest::runner: TX len : 34
2023-01-20T10:43:56.526880Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [45, 48, 38, 251, 10, 62, 215, 215, 252, 169, 222, 108, 29, 107, 218, 27, 153, 243, 38, 70, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([223, 78, 44, 100, 43, 56, 236, 173, 103, 192, 206, 246, 183, 142, 112, 92, 76, 229, 144, 94]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.530068Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10452843,
    events_root: None,
}
2023-01-20T10:43:56.530120Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 121
2023-01-20T10:43:56.530151Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::121
2023-01-20T10:43:56.530159Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.530168Z  INFO evm_eth_compliance::statetest::runner: TX len : 35
2023-01-20T10:43:56.530175Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [222, 110, 222, 138, 103, 213, 57, 57, 255, 61, 240, 251, 81, 43, 170, 57, 134, 10, 135, 126, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([8, 186, 6, 67, 64, 96, 144, 158, 241, 187, 177, 72, 238, 21, 255, 151, 138, 191, 199, 164]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.533389Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10436210,
    events_root: None,
}
2023-01-20T10:43:56.533444Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 122
2023-01-20T10:43:56.533476Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::122
2023-01-20T10:43:56.533484Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.533494Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-20T10:43:56.533501Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [53, 165, 33, 189, 186, 172, 143, 57, 201, 224, 71, 79, 215, 71, 154, 83, 174, 4, 169, 177, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([237, 181, 122, 145, 236, 15, 158, 96, 44, 228, 187, 9, 112, 215, 140, 249, 8, 152, 146, 170]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.536674Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10437202,
    events_root: None,
}
2023-01-20T10:43:56.536727Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 123
2023-01-20T10:43:56.536758Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::123
2023-01-20T10:43:56.536766Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.536775Z  INFO evm_eth_compliance::statetest::runner: TX len : 38
2023-01-20T10:43:56.536784Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [163, 190, 59, 46, 204, 133, 215, 135, 124, 109, 192, 179, 201, 158, 163, 183, 32, 218, 128, 129, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([243, 26, 71, 78, 147, 101, 63, 173, 85, 151, 169, 42, 216, 35, 72, 69, 198, 202, 167, 163]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.540671Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12175771,
    events_root: None,
}
2023-01-20T10:43:56.540763Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 124
2023-01-20T10:43:56.540817Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::124
2023-01-20T10:43:56.540825Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.540832Z  INFO evm_eth_compliance::statetest::runner: TX len : 39
2023-01-20T10:43:56.540838Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [216, 71, 151, 18, 248, 247, 200, 234, 125, 236, 48, 3, 122, 109, 203, 102, 61, 143, 102, 155, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([169, 185, 9, 5, 6, 21, 126, 14, 158, 173, 227, 210, 205, 146, 96, 62, 24, 7, 193, 75]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.544475Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11801518,
    events_root: None,
}
2023-01-20T10:43:56.544528Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 125
2023-01-20T10:43:56.544558Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::125
2023-01-20T10:43:56.544565Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.544572Z  INFO evm_eth_compliance::statetest::runner: TX len : 40
2023-01-20T10:43:56.544578Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [240, 105, 111, 142, 192, 0, 112, 37, 118, 56, 127, 110, 210, 11, 158, 218, 72, 111, 236, 95, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([228, 144, 171, 222, 65, 119, 235, 22, 184, 185, 153, 171, 81, 109, 191, 50, 48, 201, 190, 217]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.547856Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10974062,
    events_root: None,
}
2023-01-20T10:43:56.547910Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 126
2023-01-20T10:43:56.547939Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::126
2023-01-20T10:43:56.547946Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.547954Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.547960Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [120, 19, 93, 49, 27, 95, 29, 163, 243, 80, 206, 219, 91, 179, 40, 36, 232, 170, 102, 115, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([255, 208, 62, 126, 202, 215, 118, 35, 139, 166, 81, 28, 213, 37, 106, 76, 6, 119, 34, 246]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.551290Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11279691,
    events_root: None,
}
2023-01-20T10:43:56.551341Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 127
2023-01-20T10:43:56.551370Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::127
2023-01-20T10:43:56.551377Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.551384Z  INFO evm_eth_compliance::statetest::runner: TX len : 42
2023-01-20T10:43:56.551390Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [236, 125, 226, 17, 26, 107, 145, 20, 9, 209, 75, 235, 149, 115, 186, 50, 93, 188, 45, 175, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([248, 55, 7, 48, 166, 21, 107, 17, 26, 173, 99, 190, 103, 21, 128, 34, 158, 34, 144, 31]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.554690Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11429265,
    events_root: None,
}
2023-01-20T10:43:56.554742Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 128
2023-01-20T10:43:56.554769Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::128
2023-01-20T10:43:56.554776Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.554783Z  INFO evm_eth_compliance::statetest::runner: TX len : 45
2023-01-20T10:43:56.554790Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [6, 215, 163, 171, 191, 111, 61, 108, 176, 61, 123, 141, 175, 133, 131, 8, 164, 182, 98, 228, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([42, 253, 248, 192, 84, 117, 176, 132, 31, 67, 173, 185, 128, 98, 202, 213, 18, 165, 72, 166]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.558162Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10950850,
    events_root: None,
}
2023-01-20T10:43:56.558253Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 129
2023-01-20T10:43:56.558306Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::129
2023-01-20T10:43:56.558318Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.558329Z  INFO evm_eth_compliance::statetest::runner: TX len : 50
2023-01-20T10:43:56.558338Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [94, 255, 206, 61, 242, 226, 1, 215, 65, 54, 79, 65, 189, 193, 217, 19, 46, 61, 164, 42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([35, 125, 7, 240, 128, 5, 214, 16, 12, 232, 51, 219, 207, 72, 207, 226, 165, 136, 250, 212]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.562238Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12189543,
    events_root: None,
}
2023-01-20T10:43:56.562301Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 130
2023-01-20T10:43:56.562340Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::130
2023-01-20T10:43:56.562348Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.562356Z  INFO evm_eth_compliance::statetest::runner: TX len : 50
2023-01-20T10:43:56.562362Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [245, 166, 230, 23, 113, 224, 81, 170, 223, 170, 218, 47, 4, 195, 201, 221, 7, 116, 148, 92, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([99, 161, 248, 90, 214, 108, 251, 112, 175, 254, 127, 114, 241, 14, 101, 177, 241, 197, 107, 219]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.565841Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11858105,
    events_root: None,
}
2023-01-20T10:43:56.565901Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 131
2023-01-20T10:43:56.565935Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::131
2023-01-20T10:43:56.565942Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.565949Z  INFO evm_eth_compliance::statetest::runner: TX len : 48
2023-01-20T10:43:56.565956Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [104, 188, 14, 49, 10, 82, 33, 203, 66, 77, 35, 11, 209, 245, 226, 223, 197, 94, 230, 91, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([203, 139, 27, 28, 247, 17, 165, 31, 106, 220, 66, 11, 163, 247, 235, 72, 212, 100, 215, 88]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.569276Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11245058,
    events_root: None,
}
2023-01-20T10:43:56.569330Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 132
2023-01-20T10:43:56.569360Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::132
2023-01-20T10:43:56.569368Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.569376Z  INFO evm_eth_compliance::statetest::runner: TX len : 46
2023-01-20T10:43:56.569382Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [151, 146, 49, 96, 43, 223, 176, 173, 74, 237, 94, 35, 169, 161, 31, 86, 11, 248, 220, 173, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([214, 146, 119, 65, 180, 179, 79, 171, 186, 236, 1, 171, 84, 120, 90, 241, 213, 77, 143, 123]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.573832Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12178833,
    events_root: None,
}
2023-01-20T10:43:56.573932Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 133
2023-01-20T10:43:56.573989Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::133
2023-01-20T10:43:56.573996Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.574005Z  INFO evm_eth_compliance::statetest::runner: TX len : 44
2023-01-20T10:43:56.574011Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [10, 246, 118, 98, 222, 194, 191, 23, 11, 71, 183, 213, 105, 224, 131, 141, 173, 168, 27, 51, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([39, 219, 111, 43, 52, 4, 90, 240, 84, 85, 113, 232, 212, 214, 145, 54, 44, 100, 229, 34]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.577484Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11266972,
    events_root: None,
}
2023-01-20T10:43:56.577535Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 134
2023-01-20T10:43:56.577565Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::134
2023-01-20T10:43:56.577572Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.577579Z  INFO evm_eth_compliance::statetest::runner: TX len : 47
2023-01-20T10:43:56.577585Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [112, 222, 108, 157, 71, 10, 234, 224, 175, 184, 105, 10, 81, 140, 133, 185, 52, 220, 139, 254, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([17, 229, 4, 63, 151, 222, 240, 212, 67, 173, 119, 103, 18, 90, 89, 70, 153, 242, 98, 241]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.580850Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10947351,
    events_root: None,
}
2023-01-20T10:43:56.580907Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 135
2023-01-20T10:43:56.580941Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::135
2023-01-20T10:43:56.580948Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.580961Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:43:56.580967Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [207, 65, 62, 224, 159, 188, 173, 112, 156, 86, 121, 119, 198, 51, 168, 207, 9, 91, 78, 244, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([234, 42, 254, 232, 58, 98, 183, 253, 181, 137, 119, 217, 54, 57, 89, 68, 169, 197, 213, 131]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.584223Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10440940,
    events_root: None,
}
2023-01-20T10:43:56.584276Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 136
2023-01-20T10:43:56.584306Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::136
2023-01-20T10:43:56.584313Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.584321Z  INFO evm_eth_compliance::statetest::runner: TX len : 58
2023-01-20T10:43:56.584327Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [105, 201, 121, 20, 149, 124, 27, 15, 140, 103, 151, 254, 135, 229, 180, 0, 3, 91, 107, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([220, 207, 191, 236, 139, 125, 217, 233, 20, 18, 80, 156, 189, 143, 28, 37, 50, 111, 220, 220]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.587715Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11774216,
    events_root: None,
}
2023-01-20T10:43:56.587767Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 137
2023-01-20T10:43:56.587796Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::137
2023-01-20T10:43:56.587803Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.587811Z  INFO evm_eth_compliance::statetest::runner: TX len : 50
2023-01-20T10:43:56.587817Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [217, 49, 63, 116, 247, 201, 199, 225, 90, 131, 30, 214, 200, 203, 243, 184, 205, 235, 79, 104, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([197, 59, 140, 9, 245, 120, 3, 75, 172, 161, 7, 77, 167, 110, 167, 141, 46, 5, 42, 152]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.591689Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11001170,
    events_root: None,
}
2023-01-20T10:43:56.591784Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 138
2023-01-20T10:43:56.591838Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::138
2023-01-20T10:43:56.591847Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.591855Z  INFO evm_eth_compliance::statetest::runner: TX len : 50
2023-01-20T10:43:56.591861Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [180, 228, 248, 135, 90, 176, 108, 188, 150, 67, 239, 74, 178, 45, 19, 89, 9, 90, 194, 43, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([115, 145, 229, 105, 188, 148, 222, 212, 231, 8, 127, 9, 147, 56, 89, 20, 146, 88, 71, 187]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.595621Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11963521,
    events_root: None,
}
2023-01-20T10:43:56.595678Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 139
2023-01-20T10:43:56.595711Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::139
2023-01-20T10:43:56.595718Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.595725Z  INFO evm_eth_compliance::statetest::runner: TX len : 44
2023-01-20T10:43:56.595732Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [228, 202, 37, 192, 60, 31, 216, 97, 227, 135, 115, 11, 90, 22, 198, 107, 15, 23, 15, 139, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([97, 174, 177, 201, 114, 120, 98, 173, 73, 35, 140, 150, 210, 42, 73, 63, 224, 227, 123, 238]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.599186Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11377678,
    events_root: None,
}
2023-01-20T10:43:56.599247Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 140
2023-01-20T10:43:56.599278Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::140
2023-01-20T10:43:56.599286Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.599293Z  INFO evm_eth_compliance::statetest::runner: TX len : 52
2023-01-20T10:43:56.599300Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [204, 12, 246, 151, 135, 173, 80, 213, 144, 9, 105, 148, 48, 30, 148, 144, 28, 156, 18, 69, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([167, 26, 218, 136, 54, 131, 12, 3, 54, 184, 217, 150, 250, 224, 100, 33, 120, 15, 180, 222]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.602767Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11454637,
    events_root: None,
}
2023-01-20T10:43:56.602818Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 141
2023-01-20T10:43:56.602848Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::141
2023-01-20T10:43:56.602855Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.602862Z  INFO evm_eth_compliance::statetest::runner: TX len : 53
2023-01-20T10:43:56.602868Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [21, 46, 99, 166, 66, 212, 238, 147, 172, 28, 204, 13, 155, 190, 90, 167, 173, 11, 244, 90, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([64, 248, 54, 129, 215, 152, 69, 226, 199, 154, 99, 48, 210, 55, 190, 142, 170, 54, 178, 250]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.606983Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10965144,
    events_root: None,
}
2023-01-20T10:43:56.607077Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 142
2023-01-20T10:43:56.607131Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::142
2023-01-20T10:43:56.607139Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.607146Z  INFO evm_eth_compliance::statetest::runner: TX len : 53
2023-01-20T10:43:56.607152Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [34, 190, 58, 14, 174, 93, 57, 248, 252, 33, 60, 3, 218, 195, 150, 73, 24, 106, 66, 213, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([251, 210, 73, 223, 169, 243, 50, 204, 123, 142, 76, 211, 250, 176, 210, 141, 170, 42, 164, 125]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.610602Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10444079,
    events_root: None,
}
2023-01-20T10:43:56.610654Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 143
2023-01-20T10:43:56.610685Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::143
2023-01-20T10:43:56.610692Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.610700Z  INFO evm_eth_compliance::statetest::runner: TX len : 53
2023-01-20T10:43:56.610706Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [86, 116, 6, 219, 198, 120, 182, 174, 227, 221, 138, 24, 38, 248, 203, 191, 165, 228, 165, 44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([83, 22, 236, 114, 253, 231, 243, 179, 191, 237, 119, 192, 164, 196, 184, 222, 37, 19, 79, 84]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.614275Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12197222,
    events_root: None,
}
2023-01-20T10:43:56.614356Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 144
2023-01-20T10:43:56.614397Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::144
2023-01-20T10:43:56.614408Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.614419Z  INFO evm_eth_compliance::statetest::runner: TX len : 47
2023-01-20T10:43:56.614428Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [220, 159, 30, 58, 106, 239, 88, 234, 133, 7, 190, 207, 232, 170, 101, 213, 127, 236, 31, 241, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([242, 168, 62, 123, 115, 51, 145, 17, 0, 11, 61, 31, 182, 154, 64, 14, 126, 99, 133, 234]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.617986Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12288526,
    events_root: None,
}
2023-01-20T10:43:56.618039Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 145
2023-01-20T10:43:56.618069Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::145
2023-01-20T10:43:56.618075Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.618083Z  INFO evm_eth_compliance::statetest::runner: TX len : 48
2023-01-20T10:43:56.618089Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [26, 230, 145, 116, 32, 92, 98, 252, 134, 83, 101, 65, 19, 126, 158, 152, 223, 150, 158, 186, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([195, 12, 169, 231, 217, 150, 127, 224, 228, 236, 133, 227, 79, 106, 179, 54, 248, 83, 25, 176]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.622038Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12151525,
    events_root: None,
}
2023-01-20T10:43:56.622103Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 146
2023-01-20T10:43:56.622140Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::146
2023-01-20T10:43:56.622147Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.622155Z  INFO evm_eth_compliance::statetest::runner: TX len : 43
2023-01-20T10:43:56.622161Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [113, 193, 249, 113, 163, 105, 1, 98, 53, 115, 76, 35, 103, 202, 134, 169, 193, 163, 232, 90, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([64, 246, 237, 81, 54, 102, 49, 147, 90, 42, 233, 154, 124, 25, 119, 224, 237, 213, 255, 178]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.625702Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11793680,
    events_root: None,
}
2023-01-20T10:43:56.625782Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 147
2023-01-20T10:43:56.625822Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::147
2023-01-20T10:43:56.625830Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.625838Z  INFO evm_eth_compliance::statetest::runner: TX len : 44
2023-01-20T10:43:56.625844Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [55, 249, 187, 239, 145, 179, 79, 186, 116, 129, 134, 210, 165, 200, 126, 239, 141, 228, 195, 26, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([41, 235, 99, 150, 178, 91, 236, 177, 51, 242, 200, 231, 183, 53, 59, 146, 244, 76, 76, 98]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.629475Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10433760,
    events_root: None,
}
2023-01-20T10:43:56.629533Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 148
2023-01-20T10:43:56.629570Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::148
2023-01-20T10:43:56.629578Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.629585Z  INFO evm_eth_compliance::statetest::runner: TX len : 45
2023-01-20T10:43:56.629591Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [71, 161, 53, 231, 147, 21, 207, 12, 47, 89, 17, 36, 57, 128, 6, 94, 8, 74, 119, 115, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([188, 13, 157, 172, 176, 114, 87, 154, 126, 34, 188, 20, 41, 173, 15, 163, 208, 159, 214, 54]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.633150Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11269079,
    events_root: None,
}
2023-01-20T10:43:56.633205Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 149
2023-01-20T10:43:56.633238Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::149
2023-01-20T10:43:56.633246Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.633253Z  INFO evm_eth_compliance::statetest::runner: TX len : 52
2023-01-20T10:43:56.633259Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [173, 67, 124, 214, 173, 33, 167, 232, 53, 99, 89, 11, 192, 91, 207, 169, 145, 248, 240, 145, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([43, 153, 153, 151, 7, 100, 35, 29, 81, 219, 220, 164, 247, 226, 90, 83, 45, 156, 235, 74]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.636654Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11275321,
    events_root: None,
}
2023-01-20T10:43:56.636705Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 150
2023-01-20T10:43:56.636734Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::150
2023-01-20T10:43:56.636741Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.636748Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:43:56.636754Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [118, 253, 129, 235, 110, 181, 112, 67, 133, 47, 193, 51, 232, 63, 54, 80, 54, 139, 88, 125, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([95, 237, 89, 139, 110, 49, 65, 224, 60, 60, 20, 229, 3, 22, 21, 4, 58, 55, 198, 210]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.640717Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11367661,
    events_root: None,
}
2023-01-20T10:43:56.640806Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 151
2023-01-20T10:43:56.640857Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::151
2023-01-20T10:43:56.640865Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.640874Z  INFO evm_eth_compliance::statetest::runner: TX len : 54
2023-01-20T10:43:56.640880Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [118, 73, 206, 119, 237, 188, 95, 40, 75, 52, 120, 211, 108, 113, 191, 205, 211, 201, 36, 66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([105, 205, 236, 113, 108, 6, 4, 33, 195, 172, 235, 69, 231, 194, 10, 70, 44, 57, 179, 196]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.644505Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12099204,
    events_root: None,
}
2023-01-20T10:43:56.644559Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 152
2023-01-20T10:43:56.644589Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::152
2023-01-20T10:43:56.644596Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.644603Z  INFO evm_eth_compliance::statetest::runner: TX len : 56
2023-01-20T10:43:56.644609Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [20, 172, 28, 173, 94, 95, 245, 0, 185, 177, 117, 167, 31, 215, 149, 16, 63, 44, 19, 139, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([181, 234, 212, 57, 130, 55, 33, 105, 194, 150, 21, 133, 199, 153, 93, 4, 88, 59, 115, 186]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.648178Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11342029,
    events_root: None,
}
2023-01-20T10:43:56.648233Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 153
2023-01-20T10:43:56.648265Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::153
2023-01-20T10:43:56.648272Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.648279Z  INFO evm_eth_compliance::statetest::runner: TX len : 58
2023-01-20T10:43:56.648285Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [26, 101, 176, 69, 84, 51, 18, 241, 127, 107, 40, 74, 18, 220, 174, 49, 61, 184, 176, 46, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([200, 217, 188, 25, 220, 251, 23, 179, 218, 227, 166, 22, 94, 144, 26, 60, 73, 8, 70, 138]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.651760Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11780166,
    events_root: None,
}
2023-01-20T10:43:56.651813Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 154
2023-01-20T10:43:56.651842Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::154
2023-01-20T10:43:56.651849Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.651857Z  INFO evm_eth_compliance::statetest::runner: TX len : 65
2023-01-20T10:43:56.651863Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [35, 128, 1, 174, 185, 69, 54, 247, 121, 157, 168, 150, 3, 116, 226, 58, 172, 212, 69, 225, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([31, 163, 144, 252, 182, 248, 233, 152, 102, 202, 123, 160, 52, 25, 182, 48, 42, 126, 125, 127]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.655818Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12184857,
    events_root: None,
}
2023-01-20T10:43:56.655911Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 155
2023-01-20T10:43:56.655969Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::155
2023-01-20T10:43:56.655982Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.655993Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.656001Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [189, 150, 142, 177, 252, 159, 80, 98, 216, 24, 12, 228, 161, 110, 140, 30, 24, 251, 166, 59, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([143, 48, 151, 243, 120, 89, 27, 129, 230, 249, 182, 62, 246, 236, 88, 132, 133, 35, 11, 98]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.659858Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12313075,
    events_root: None,
}
2023-01-20T10:43:56.659916Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 156
2023-01-20T10:43:56.659952Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::156
2023-01-20T10:43:56.659960Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.659967Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.659973Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [133, 123, 97, 186, 230, 150, 134, 232, 48, 18, 28, 53, 2, 106, 71, 246, 229, 201, 107, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([225, 90, 38, 122, 66, 192, 22, 132, 157, 186, 48, 208, 20, 183, 225, 129, 28, 153, 191, 143]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.663169Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10434356,
    events_root: None,
}
2023-01-20T10:43:56.663220Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 157
2023-01-20T10:43:56.663250Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::157
2023-01-20T10:43:56.663256Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.663263Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T10:43:56.663270Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [119, 43, 12, 213, 37, 161, 182, 189, 226, 81, 125, 114, 171, 147, 1, 215, 20, 205, 66, 51, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([207, 106, 230, 36, 128, 3, 64, 97, 112, 155, 53, 242, 49, 58, 211, 183, 163, 130, 183, 38]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.666848Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11313252,
    events_root: None,
}
2023-01-20T10:43:56.666913Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 158
2023-01-20T10:43:56.666950Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::158
2023-01-20T10:43:56.666957Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.666964Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:43:56.666971Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [6, 35, 118, 194, 196, 153, 32, 200, 249, 249, 149, 56, 217, 3, 160, 121, 59, 224, 67, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([160, 235, 122, 2, 215, 254, 201, 155, 119, 78, 235, 192, 60, 113, 223, 58, 1, 185, 60, 85]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.670250Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10440660,
    events_root: None,
}
2023-01-20T10:43:56.670301Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 159
2023-01-20T10:43:56.670331Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::159
2023-01-20T10:43:56.670338Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.670345Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:43:56.670352Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [150, 142, 190, 167, 13, 28, 140, 20, 24, 161, 4, 241, 242, 157, 66, 71, 147, 54, 225, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([52, 213, 157, 186, 11, 97, 223, 186, 141, 145, 5, 181, 198, 184, 50, 254, 105, 198, 22, 17]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.674783Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11824037,
    events_root: None,
}
2023-01-20T10:43:56.674906Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 160
2023-01-20T10:43:56.674975Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::160
2023-01-20T10:43:56.674997Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.675014Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:43:56.675030Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [215, 137, 74, 235, 136, 118, 112, 25, 57, 244, 106, 108, 141, 150, 106, 204, 39, 135, 197, 54, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([121, 49, 230, 26, 61, 225, 100, 172, 133, 175, 68, 18, 123, 99, 123, 35, 106, 40, 238, 75]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.679687Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12234608,
    events_root: None,
}
2023-01-20T10:43:56.679767Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 161
2023-01-20T10:43:56.679815Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::161
2023-01-20T10:43:56.679826Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.679836Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:43:56.679845Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [241, 57, 177, 145, 96, 12, 23, 25, 218, 82, 20, 176, 89, 201, 25, 246, 50, 83, 167, 63, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([182, 6, 185, 18, 133, 16, 215, 245, 36, 217, 66, 177, 231, 21, 254, 217, 58, 11, 229, 93]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.683658Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11810842,
    events_root: None,
}
2023-01-20T10:43:56.683715Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 162
2023-01-20T10:43:56.683748Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::162
2023-01-20T10:43:56.683755Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.683763Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:43:56.683768Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [109, 169, 70, 193, 200, 168, 210, 178, 199, 85, 135, 68, 202, 200, 226, 169, 9, 41, 249, 28, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([167, 124, 11, 203, 117, 104, 178, 126, 106, 103, 144, 179, 101, 101, 249, 198, 8, 24, 120, 106]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.687875Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11273675,
    events_root: None,
}
2023-01-20T10:43:56.687960Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 163
2023-01-20T10:43:56.688011Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::163
2023-01-20T10:43:56.688019Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.688027Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T10:43:56.688033Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [15, 15, 61, 221, 156, 207, 62, 175, 209, 247, 1, 11, 248, 252, 0, 71, 84, 106, 36, 141, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([158, 244, 122, 14, 138, 53, 31, 2, 77, 188, 36, 151, 210, 57, 189, 97, 56, 70, 38, 8]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.691740Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11335513,
    events_root: None,
}
2023-01-20T10:43:56.691799Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 164
2023-01-20T10:43:56.691839Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::164
2023-01-20T10:43:56.691847Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.691854Z  INFO evm_eth_compliance::statetest::runner: TX len : 55
2023-01-20T10:43:56.691860Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [86, 211, 218, 69, 66, 23, 63, 85, 104, 188, 152, 35, 89, 104, 250, 88, 188, 60, 139, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([129, 159, 66, 60, 246, 4, 104, 99, 223, 43, 143, 209, 74, 199, 65, 71, 140, 231, 24, 26]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.695301Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11276097,
    events_root: None,
}
2023-01-20T10:43:56.695380Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 165
2023-01-20T10:43:56.695426Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::165
2023-01-20T10:43:56.695438Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.695449Z  INFO evm_eth_compliance::statetest::runner: TX len : 55
2023-01-20T10:43:56.695458Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [52, 218, 217, 188, 90, 181, 117, 221, 216, 228, 161, 128, 108, 133, 15, 185, 94, 131, 102, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([121, 65, 156, 7, 131, 113, 102, 22, 42, 60, 154, 16, 44, 92, 72, 50, 166, 65, 206, 71]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.699852Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11325291,
    events_root: None,
}
2023-01-20T10:43:56.699931Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 166
2023-01-20T10:43:56.699977Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::166
2023-01-20T10:43:56.699988Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.699997Z  INFO evm_eth_compliance::statetest::runner: TX len : 55
2023-01-20T10:43:56.700006Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [193, 110, 57, 217, 175, 140, 2, 177, 120, 231, 56, 26, 117, 114, 32, 45, 118, 170, 233, 109, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([134, 70, 73, 170, 33, 5, 210, 145, 113, 224, 8, 209, 199, 155, 193, 121, 145, 6, 60, 206]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.704005Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 11336241,
    events_root: None,
}
2023-01-20T10:43:56.704057Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 167
2023-01-20T10:43:56.704088Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::167
2023-01-20T10:43:56.704095Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.704103Z  INFO evm_eth_compliance::statetest::runner: TX len : 24
2023-01-20T10:43:56.704108Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [175, 94, 74, 203, 37, 137, 155, 229, 20, 17, 223, 73, 40, 229, 83, 55, 16, 194, 66, 22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([69, 33, 61, 219, 236, 177, 108, 152, 57, 114, 66, 61, 46, 67, 157, 180, 180, 247, 180, 103]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.707648Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10955315,
    events_root: None,
}
2023-01-20T10:43:56.707732Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 168
2023-01-20T10:43:56.707774Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE_EOF1Invalid"::Shanghai::168
2023-01-20T10:43:56.707781Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.707788Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-20T10:43:56.707795Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [191, 141, 204, 113, 132, 232, 36, 79, 221, 105, 101, 126, 112, 95, 156, 49, 150, 69, 115, 218, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([106, 50, 122, 229, 134, 4, 239, 132, 232, 253, 155, 185, 54, 57, 80, 249, 57, 82, 203, 38]) }
[DEBUG] getting cid: bafy2bzacebjifzkc2c4zd3sbqmk3cmy4p7grkhiubs4prpjvlhvoktsl6zmd2
[DEBUG] fetching parameters block: 1
2023-01-20T10:43:56.711554Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 10972838,
    events_root: None,
}
2023-01-20T10:43:56.713392Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE_EOF1Invalid.json"
2023-01-20T10:43:56.713732Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:13.380572705s
```