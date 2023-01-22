> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| KO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json \
	cargo run \
	-- \
	statetest
```

> For Review

- Execution Looks OK, no error.

> Opcode

@0x00000000000000000000000000000000000c0dec

```
Too Big
```

> Execution Trace

```
2023-01-22T14:21:41.697752Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json", Total Files :: 1
2023-01-22T14:21:41.698220Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:41.811575Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 13, 236, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.702617Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-22T14:21:53.703034Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T14:21:53.703119Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 222, 16, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzacebcbvotpkkkxgcpp535g6oa2pvu7u65o2whukjypah76w75m5eank
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.706385Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-22T14:21:53.706528Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T14:21:53.706574Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 222, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([135, 86, 195, 226, 17, 192, 42, 192, 25, 213, 136, 254, 18, 95, 50, 68, 155, 121, 209, 130]) }
[DEBUG] getting cid: bafy2bzaceawkzltaqdnhv2a3iwi4vvxj3d5isrqfrgrzznsyt5mjqexz2sgaq
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.709816Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [202]
2023-01-22T14:21:53.709971Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T14:21:53.710018Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 192, 222, 16, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([121, 46, 44, 168, 100, 157, 195, 57, 208, 185, 119, 244, 82, 48, 8, 55, 203, 168, 19, 62]) }
[DEBUG] getting cid: bafy2bzacebxlye5kuf46clpq6gtlhmevlewshitcfsxh2okh22tavhgptn2rk
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.712953Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [203]
2023-01-22T14:21:53.713096Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T14:21:53.713146Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([102, 145, 95, 210, 114, 99, 97, 196, 103, 113, 159, 135, 176, 147, 142, 56, 188, 98, 191, 170]) }
[DEBUG] getting cid: bafy2bzacebjynazs2odnerikgpdpcakug3momzsx4xjc4vpoys7huytyke42a
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.716450Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [204]
2023-01-22T14:21:53.716609Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T14:21:53.717834Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-22T14:21:53.717880Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::London::0
2023-01-22T14:21:53.717889Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.717897Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.717904Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [212, 231, 174, 8, 49, 50, 146, 90, 73, 39, 193, 245, 129, 98, 56, 186, 23, 184, 42, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
[DEBUG] getting cid: bafy2bzacecxdfhvel2hrsnjaughfeqewm2mqox5dxydmxfnn5ortx364wd2jc
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.723184Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 19163573,
    events_root: None,
}
2023-01-22T14:21:53.723255Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-22T14:21:53.723279Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::London::2
2023-01-22T14:21:53.723287Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.723294Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.723301Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [116, 225, 98, 90, 58, 165, 113, 101, 125, 102, 247, 164, 18, 179, 22, 10, 24, 100, 59, 199, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
[DEBUG] getting cid: bafy2bzacecxdfhvel2hrsnjaughfeqewm2mqox5dxydmxfnn5ortx364wd2jc
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.728929Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 21899965,
    events_root: None,
}
2023-01-22T14:21:53.729001Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-22T14:21:53.729025Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::London::4
2023-01-22T14:21:53.729033Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.729040Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.729046Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [118, 185, 211, 247, 155, 64, 85, 250, 32, 132, 121, 169, 211, 200, 87, 186, 184, 96, 25, 79, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
[DEBUG] getting cid: bafy2bzacecxdfhvel2hrsnjaughfeqewm2mqox5dxydmxfnn5ortx364wd2jc
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.734635Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 21723629,
    events_root: None,
}
2023-01-22T14:21:53.734704Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 11
2023-01-22T14:21:53.734729Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::London::11
2023-01-22T14:21:53.734736Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.734743Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.734749Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [80, 255, 121, 74, 82, 144, 194, 114, 154, 34, 118, 176, 45, 222, 95, 32, 168, 29, 151, 254, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
[DEBUG] getting cid: bafy2bzacecxdfhvel2hrsnjaughfeqewm2mqox5dxydmxfnn5ortx364wd2jc
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.740825Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 21264527,
    events_root: None,
}
2023-01-22T14:21:53.740920Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-22T14:21:53.740964Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::London::0
2023-01-22T14:21:53.740972Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.740979Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.740986Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [13, 133, 94, 51, 136, 124, 111, 86, 36, 2, 200, 3, 61, 38, 95, 220, 147, 46, 68, 108, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([236, 70, 216, 243, 101, 99, 189, 62, 205, 26, 208, 253, 84, 36, 48, 143, 166, 88, 135, 41]) }
[DEBUG] getting cid: bafy2bzacecxdfhvel2hrsnjaughfeqewm2mqox5dxydmxfnn5ortx364wd2jc
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.746664Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 20925719,
    events_root: None,
}
2023-01-22T14:21:53.746735Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-22T14:21:53.746761Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::London::2
2023-01-22T14:21:53.746768Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.746775Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.746781Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [49, 185, 63, 191, 213, 155, 73, 165, 179, 122, 175, 16, 117, 47, 61, 21, 145, 164, 200, 202, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([155, 99, 140, 31, 46, 96, 27, 93, 44, 60, 131, 66, 80, 136, 87, 209, 224, 27, 216, 212]) }
[DEBUG] getting cid: bafy2bzacecxdfhvel2hrsnjaughfeqewm2mqox5dxydmxfnn5ortx364wd2jc
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.752227Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 21238050,
    events_root: None,
}
2023-01-22T14:21:53.752297Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-22T14:21:53.752321Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::London::4
2023-01-22T14:21:53.752328Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.752335Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.752341Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [91, 49, 82, 209, 139, 224, 218, 68, 68, 230, 129, 76, 151, 202, 10, 192, 56, 158, 185, 137, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([188, 149, 186, 245, 1, 91, 222, 203, 63, 25, 86, 169, 35, 110, 18, 124, 122, 60, 238, 128]) }
[DEBUG] getting cid: bafy2bzacecxdfhvel2hrsnjaughfeqewm2mqox5dxydmxfnn5ortx364wd2jc
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.757923Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 22015683,
    events_root: None,
}
2023-01-22T14:21:53.757993Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 11
2023-01-22T14:21:53.758017Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::London::11
2023-01-22T14:21:53.758024Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.758032Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.758038Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [240, 82, 158, 237, 115, 153, 246, 17, 81, 0, 74, 37, 251, 72, 112, 26, 90, 25, 105, 187, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([20, 3, 204, 71, 166, 252, 88, 221, 29, 77, 14, 224, 191, 132, 61, 100, 47, 53, 166, 175]) }
[DEBUG] getting cid: bafy2bzacecxdfhvel2hrsnjaughfeqewm2mqox5dxydmxfnn5ortx364wd2jc
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.763659Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 21274186,
    events_root: None,
}
2023-01-22T14:21:53.763753Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-22T14:21:53.763794Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::London::1
2023-01-22T14:21:53.763802Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.763810Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.763816Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.767046Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12712809,
    events_root: None,
}
2023-01-22T14:21:53.767093Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-22T14:21:53.767117Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::London::1
2023-01-22T14:21:53.767125Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.767132Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.767138Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.770256Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12712809,
    events_root: None,
}
2023-01-22T14:21:53.770303Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 12
2023-01-22T14:21:53.770326Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::London::12
2023-01-22T14:21:53.770333Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.770340Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.770346Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.773473Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12747321,
    events_root: None,
}
2023-01-22T14:21:53.773518Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 12
2023-01-22T14:21:53.773541Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::London::12
2023-01-22T14:21:53.773549Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.773556Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.773561Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.776932Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12747321,
    events_root: None,
}
2023-01-22T14:21:53.776995Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-22T14:21:53.777035Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::London::3
2023-01-22T14:21:53.777043Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.777051Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.777057Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.780288Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12719085,
    events_root: None,
}
2023-01-22T14:21:53.780335Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-22T14:21:53.780358Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::London::3
2023-01-22T14:21:53.780366Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.780374Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.780380Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.783575Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12719085,
    events_root: None,
}
2023-01-22T14:21:53.783622Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-22T14:21:53.783645Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::London::5
2023-01-22T14:21:53.783652Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.783659Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.783666Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.786882Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12725349,
    events_root: None,
}
2023-01-22T14:21:53.786928Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-22T14:21:53.786951Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::London::5
2023-01-22T14:21:53.786960Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.786966Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.786972Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.790155Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12725349,
    events_root: None,
}
2023-01-22T14:21:53.790202Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 10
2023-01-22T14:21:53.790224Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::London::10
2023-01-22T14:21:53.790232Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.790239Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.790245Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.793411Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12169196,
    events_root: None,
}
2023-01-22T14:21:53.793463Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 10
2023-01-22T14:21:53.793494Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::London::10
2023-01-22T14:21:53.793502Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.793509Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.793515Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.796648Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12169196,
    events_root: None,
}
2023-01-22T14:21:53.796700Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 6
2023-01-22T14:21:53.796733Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::London::6
2023-01-22T14:21:53.796741Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.796748Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.796754Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.799982Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12125848,
    events_root: None,
}
2023-01-22T14:21:53.800028Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 7
2023-01-22T14:21:53.800051Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::London::7
2023-01-22T14:21:53.800058Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.800065Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.800071Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.803017Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12165880,
    events_root: None,
}
2023-01-22T14:21:53.803060Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 8
2023-01-22T14:21:53.803084Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::London::8
2023-01-22T14:21:53.803091Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.803098Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.803103Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.806207Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12135096,
    events_root: None,
}
2023-01-22T14:21:53.806253Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 9
2023-01-22T14:21:53.806275Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::London::9
2023-01-22T14:21:53.806282Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.806290Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.806295Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.809204Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12175128,
    events_root: None,
}
2023-01-22T14:21:53.809249Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 6
2023-01-22T14:21:53.809272Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::London::6
2023-01-22T14:21:53.809279Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.809286Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.809292Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.812399Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12125848,
    events_root: None,
}
2023-01-22T14:21:53.812466Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 7
2023-01-22T14:21:53.812512Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::London::7
2023-01-22T14:21:53.812520Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.812527Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.812535Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.815596Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12165880,
    events_root: None,
}
2023-01-22T14:21:53.815652Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 8
2023-01-22T14:21:53.815679Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::London::8
2023-01-22T14:21:53.815688Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.815697Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.815705Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.818603Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12135096,
    events_root: None,
}
2023-01-22T14:21:53.818649Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 9
2023-01-22T14:21:53.818672Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::London::9
2023-01-22T14:21:53.818679Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.818686Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.818692Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.821611Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12175128,
    events_root: None,
}
2023-01-22T14:21:53.821657Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 13
2023-01-22T14:21:53.821680Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::London::13
2023-01-22T14:21:53.821689Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.821696Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.821702Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [119, 109, 37, 66, 126, 10, 238, 202, 114, 14, 109, 215, 238, 52, 88, 33, 10, 34, 143, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([192, 88, 99, 161, 23, 254, 175, 39, 213, 169, 153, 253, 197, 254, 95, 117, 145, 246, 7, 95]) }
[DEBUG] getting cid: bafy2bzacecxdfhvel2hrsnjaughfeqewm2mqox5dxydmxfnn5ortx364wd2jc
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.827687Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 22764558,
    events_root: None,
}
2023-01-22T14:21:53.827778Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 13
2023-01-22T14:21:53.827813Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::London::13
2023-01-22T14:21:53.827821Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.827828Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.827834Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [141, 58, 197, 66, 171, 118, 105, 97, 81, 70, 98, 240, 157, 91, 164, 161, 18, 9, 55, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([96, 33, 187, 115, 222, 53, 224, 244, 47, 32, 70, 11, 226, 18, 129, 166, 126, 239, 230, 44]) }
[DEBUG] getting cid: bafy2bzacec56hxtjgehqehobuwodq5z3emyqlpyatqii4vnmpazhrf43pcmzo
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.834039Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 22906030,
    events_root: None,
}
2023-01-22T14:21:53.834138Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 14
2023-01-22T14:21:53.834179Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::London::14
2023-01-22T14:21:53.834187Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.834195Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.834203Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.837429Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12748378,
    events_root: None,
}
2023-01-22T14:21:53.837476Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 14
2023-01-22T14:21:53.837501Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::London::14
2023-01-22T14:21:53.837508Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.837515Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.837521Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.840622Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12752855,
    events_root: None,
}
2023-01-22T14:21:53.840673Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-22T14:21:53.840696Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::Merge::0
2023-01-22T14:21:53.840703Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.840710Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.840716Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [39, 25, 101, 133, 71, 240, 57, 195, 85, 63, 84, 183, 5, 112, 174, 23, 7, 6, 158, 221, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([125, 213, 185, 126, 102, 183, 165, 62, 81, 45, 4, 229, 242, 150, 184, 46, 206, 140, 135, 167]) }
[DEBUG] getting cid: bafy2bzacecvno3qkgjaxj4oap65zpvdgjlmgtenccyomgbmnq2prw37mtkcwe
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.845970Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 20223299,
    events_root: None,
}
2023-01-22T14:21:53.846039Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-22T14:21:53.846062Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::Merge::2
2023-01-22T14:21:53.846069Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.846076Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.846082Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [106, 52, 234, 40, 141, 116, 18, 253, 59, 221, 175, 135, 231, 236, 88, 23, 173, 98, 51, 37, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([57, 47, 201, 253, 31, 210, 216, 45, 82, 53, 15, 10, 140, 189, 182, 38, 139, 193, 227, 148]) }
[DEBUG] getting cid: bafy2bzacecvno3qkgjaxj4oap65zpvdgjlmgtenccyomgbmnq2prw37mtkcwe
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.851926Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 21888621,
    events_root: None,
}
2023-01-22T14:21:53.852019Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-22T14:21:53.852059Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::Merge::4
2023-01-22T14:21:53.852067Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.852075Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.852082Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [51, 187, 50, 100, 96, 217, 185, 81, 171, 242, 51, 149, 184, 212, 113, 50, 44, 235, 132, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([10, 128, 19, 154, 164, 202, 88, 213, 185, 231, 230, 233, 169, 125, 32, 175, 46, 247, 104, 205]) }
[DEBUG] getting cid: bafy2bzacecvno3qkgjaxj4oap65zpvdgjlmgtenccyomgbmnq2prw37mtkcwe
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.857555Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 20939407,
    events_root: None,
}
2023-01-22T14:21:53.857626Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 11
2023-01-22T14:21:53.857657Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::Merge::11
2023-01-22T14:21:53.857666Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.857673Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.857681Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [159, 241, 97, 227, 46, 194, 155, 208, 206, 71, 166, 68, 188, 211, 105, 37, 183, 134, 101, 74, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([234, 139, 137, 133, 156, 6, 41, 217, 87, 171, 216, 141, 23, 64, 208, 12, 0, 6, 118, 73]) }
[DEBUG] getting cid: bafy2bzacecvno3qkgjaxj4oap65zpvdgjlmgtenccyomgbmnq2prw37mtkcwe
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.862868Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 20172649,
    events_root: None,
}
2023-01-22T14:21:53.862934Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-22T14:21:53.862958Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::Merge::0
2023-01-22T14:21:53.862965Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.862972Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.862978Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [231, 87, 32, 90, 179, 85, 155, 113, 227, 42, 129, 42, 140, 246, 42, 181, 54, 222, 146, 226, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([74, 138, 107, 177, 65, 173, 106, 127, 111, 235, 64, 25, 56, 77, 152, 139, 121, 241, 216, 113]) }
[DEBUG] getting cid: bafy2bzacecvno3qkgjaxj4oap65zpvdgjlmgtenccyomgbmnq2prw37mtkcwe
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.868538Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 21979292,
    events_root: None,
}
2023-01-22T14:21:53.868618Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-22T14:21:53.868647Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::Merge::2
2023-01-22T14:21:53.868654Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.868661Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.868667Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [122, 109, 71, 188, 211, 251, 122, 214, 171, 21, 136, 241, 63, 234, 50, 221, 57, 22, 13, 114, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([126, 248, 213, 18, 73, 109, 79, 84, 218, 211, 209, 213, 172, 193, 146, 154, 144, 35, 152, 99]) }
[DEBUG] getting cid: bafy2bzacecvno3qkgjaxj4oap65zpvdgjlmgtenccyomgbmnq2prw37mtkcwe
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.874799Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 22078191,
    events_root: None,
}
2023-01-22T14:21:53.874881Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-22T14:21:53.874919Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::Merge::4
2023-01-22T14:21:53.874927Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.874934Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.874940Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [71, 101, 68, 41, 229, 175, 120, 27, 168, 52, 108, 53, 152, 213, 167, 51, 123, 67, 206, 55, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([167, 245, 235, 76, 86, 206, 109, 57, 189, 19, 0, 230, 242, 87, 18, 38, 208, 32, 55, 56]) }
[DEBUG] getting cid: bafy2bzacecvno3qkgjaxj4oap65zpvdgjlmgtenccyomgbmnq2prw37mtkcwe
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.880255Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 21006423,
    events_root: None,
}
2023-01-22T14:21:53.880323Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 11
2023-01-22T14:21:53.880348Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::Merge::11
2023-01-22T14:21:53.880355Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.880362Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.880368Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [124, 59, 29, 21, 146, 46, 37, 176, 163, 68, 109, 34, 230, 188, 9, 40, 152, 189, 195, 56, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([138, 192, 102, 104, 212, 54, 151, 48, 197, 195, 196, 55, 46, 91, 125, 35, 54, 100, 85, 118]) }
[DEBUG] getting cid: bafy2bzacecvno3qkgjaxj4oap65zpvdgjlmgtenccyomgbmnq2prw37mtkcwe
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.886110Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 20971512,
    events_root: None,
}
2023-01-22T14:21:53.886204Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-22T14:21:53.886245Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::Merge::1
2023-01-22T14:21:53.886253Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.886262Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.886268Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.889435Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12715616,
    events_root: None,
}
2023-01-22T14:21:53.889482Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-22T14:21:53.889506Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::Merge::1
2023-01-22T14:21:53.889513Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.889520Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.889526Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.892599Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12715616,
    events_root: None,
}
2023-01-22T14:21:53.892650Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 12
2023-01-22T14:21:53.892673Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::Merge::12
2023-01-22T14:21:53.892680Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.892687Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.892693Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.895757Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12750128,
    events_root: None,
}
2023-01-22T14:21:53.895803Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 12
2023-01-22T14:21:53.895827Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::Merge::12
2023-01-22T14:21:53.895834Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.895842Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.895848Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.898906Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12750128,
    events_root: None,
}
2023-01-22T14:21:53.898953Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-22T14:21:53.898976Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::Merge::3
2023-01-22T14:21:53.898983Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.898991Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.898997Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.902083Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12721892,
    events_root: None,
}
2023-01-22T14:21:53.902128Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-22T14:21:53.902151Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::Merge::3
2023-01-22T14:21:53.902158Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.902165Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.902171Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.905209Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12721892,
    events_root: None,
}
2023-01-22T14:21:53.905255Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-22T14:21:53.905277Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::Merge::5
2023-01-22T14:21:53.905284Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.905291Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.905297Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.908339Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12728156,
    events_root: None,
}
2023-01-22T14:21:53.908385Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-22T14:21:53.908408Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::Merge::5
2023-01-22T14:21:53.908416Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.908423Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.908429Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.911879Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12728156,
    events_root: None,
}
2023-01-22T14:21:53.911952Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 10
2023-01-22T14:21:53.911993Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::Merge::10
2023-01-22T14:21:53.912003Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.912013Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.912020Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.914988Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12171819,
    events_root: None,
}
2023-01-22T14:21:53.915033Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 10
2023-01-22T14:21:53.915057Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::Merge::10
2023-01-22T14:21:53.915064Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.915071Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.915077Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.917868Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12171819,
    events_root: None,
}
2023-01-22T14:21:53.917913Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-22T14:21:53.917936Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::Merge::6
2023-01-22T14:21:53.917943Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.917950Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.917956Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.920772Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12128655,
    events_root: None,
}
2023-01-22T14:21:53.920816Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-22T14:21:53.920839Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::Merge::7
2023-01-22T14:21:53.920847Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.920854Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.920860Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.923668Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12168687,
    events_root: None,
}
2023-01-22T14:21:53.923713Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 8
2023-01-22T14:21:53.923739Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::Merge::8
2023-01-22T14:21:53.923748Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.923755Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.923763Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.927009Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12137903,
    events_root: None,
}
2023-01-22T14:21:53.927080Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 9
2023-01-22T14:21:53.927119Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::Merge::9
2023-01-22T14:21:53.927127Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.927134Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.927140Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.930178Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12178119,
    events_root: None,
}
2023-01-22T14:21:53.930229Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-22T14:21:53.930260Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::Merge::6
2023-01-22T14:21:53.930269Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.930276Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.930282Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.933544Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12128655,
    events_root: None,
}
2023-01-22T14:21:53.933596Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-22T14:21:53.933630Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::Merge::7
2023-01-22T14:21:53.933637Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.933644Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.933651Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.936503Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12168687,
    events_root: None,
}
2023-01-22T14:21:53.936548Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 8
2023-01-22T14:21:53.936571Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::Merge::8
2023-01-22T14:21:53.936578Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.936585Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.936592Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.939370Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12137903,
    events_root: None,
}
2023-01-22T14:21:53.939415Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 9
2023-01-22T14:21:53.939438Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::Merge::9
2023-01-22T14:21:53.939446Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.939453Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.939462Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.942237Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12178119,
    events_root: None,
}
2023-01-22T14:21:53.942282Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 13
2023-01-22T14:21:53.942304Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::Merge::13
2023-01-22T14:21:53.942311Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.942318Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.942325Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [60, 100, 43, 122, 153, 42, 174, 80, 245, 174, 210, 228, 152, 201, 168, 112, 110, 49, 18, 156, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([242, 200, 122, 171, 63, 235, 198, 140, 32, 232, 76, 42, 197, 165, 51, 1, 171, 177, 228, 41]) }
[DEBUG] getting cid: bafy2bzacecvno3qkgjaxj4oap65zpvdgjlmgtenccyomgbmnq2prw37mtkcwe
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.948435Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 22906164,
    events_root: None,
}
2023-01-22T14:21:53.948542Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 13
2023-01-22T14:21:53.948584Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::Merge::13
2023-01-22T14:21:53.948592Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.948599Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.948606Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [44, 34, 234, 135, 126, 109, 150, 196, 3, 170, 51, 178, 131, 180, 78, 182, 191, 68, 146, 71, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([62, 147, 196, 228, 19, 53, 26, 163, 227, 161, 161, 215, 158, 164, 116, 190, 53, 196, 226, 86]) }
[DEBUG] getting cid: bafy2bzaced6kqpwfrlzfahs4lkejqi3kzxcgz7slkeg2egyj74wpfirhwowuq
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.954264Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 22266137,
    events_root: None,
}
2023-01-22T14:21:53.954337Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 14
2023-01-22T14:21:53.954363Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::Merge::14
2023-01-22T14:21:53.954370Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.954377Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.954383Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.957440Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12751185,
    events_root: None,
}
2023-01-22T14:21:53.957485Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 14
2023-01-22T14:21:53.957507Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateAddressWarmAfterFail"::Merge::14
2023-01-22T14:21:53.957515Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.957523Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-22T14:21:53.957529Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T14:21:53.960668Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12755663,
    events_root: None,
}
2023-01-22T14:21:53.962840Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stCreateTest/CreateAddressWarmAfterFail.json"
2023-01-22T14:21:53.963235Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:12.149163578s
```