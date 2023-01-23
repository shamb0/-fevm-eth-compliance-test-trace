> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| KO | under native RT context |

KO :: Implementation of delete_actor() is missing for test_vm runtime

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stBadOpcode/invalidAddr.json#L1


> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json \
	cargo run \
	-- \
	statetest
```


> Execution Trace

```
2023-01-22T15:16:40.329077Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json", Total Files :: 1
2023-01-22T15:16:40.329524Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:40.489090Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 222, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.533315Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-22T15:16:52.533517Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T15:16:52.533599Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 222, 173, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzacedbbb24k36qqrigv4gkgbtkuv6u2mvq4hztrydhqxxxy5qwumk776
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.536638Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-22T15:16:52.536779Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T15:16:52.536825Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 222, 173, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([135, 86, 195, 226, 17, 192, 42, 192, 25, 213, 136, 254, 18, 95, 50, 68, 155, 121, 209, 130]) }
[DEBUG] getting cid: bafy2bzacedxfi7cbcbdgs5tspu7w3e3o7orlghtj6lcjd5gbr2p4ww27ezals
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.540205Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [202]
2023-01-22T15:16:52.540344Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T15:16:52.540391Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([121, 46, 44, 168, 100, 157, 195, 57, 208, 185, 119, 244, 82, 48, 8, 55, 203, 168, 19, 62]) }
[DEBUG] getting cid: bafy2bzacebzccxwacolatqwzizmcenr7byvovcqwwqujn2abl6makvwhcqib4
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.543320Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [203]
2023-01-22T15:16:52.543459Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T15:16:52.543515Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([102, 145, 95, 210, 114, 99, 97, 196, 103, 113, 159, 135, 176, 147, 142, 56, 188, 98, 191, 170]) }
[DEBUG] getting cid: bafy2bzacecsq3tuqbkaxqsblsshzvv7oxo2knbz7qnsl22x5z5s3n7zubq35a
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.546486Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [204]
2023-01-22T15:16:52.546875Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-22T15:16:52.548115Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-22T15:16:52.548161Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::0
2023-01-22T15:16:52.548170Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.548180Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.548187Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.549522Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1918592,
    events_root: None,
}
2023-01-22T15:16:52.549573Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-22T15:16:52.549620Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::1
2023-01-22T15:16:52.549634Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.549643Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.549654Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.550413Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1881191,
    events_root: None,
}
2023-01-22T15:16:52.550442Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-22T15:16:52.550465Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::2
2023-01-22T15:16:52.550472Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.550479Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.550484Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.551187Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1943960,
    events_root: None,
}
2023-01-22T15:16:52.551215Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-22T15:16:52.551240Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::3
2023-01-22T15:16:52.551247Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.551254Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.551260Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.551876Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1906559,
    events_root: None,
}
2023-01-22T15:16:52.551903Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-22T15:16:52.551927Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::4
2023-01-22T15:16:52.551934Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.551940Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.551946Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.552606Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1955940,
    events_root: None,
}
2023-01-22T15:16:52.552635Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 5
2023-01-22T15:16:52.552659Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::5
2023-01-22T15:16:52.552665Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.552672Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.552678Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.553282Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1918539,
    events_root: None,
}
2023-01-22T15:16:52.553308Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 6
2023-01-22T15:16:52.553332Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::6
2023-01-22T15:16:52.553338Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.553345Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.553351Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.554015Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1958336,
    events_root: None,
}
2023-01-22T15:16:52.554044Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 7
2023-01-22T15:16:52.554066Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::7
2023-01-22T15:16:52.554073Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.554080Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.554086Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.554720Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1920935,
    events_root: None,
}
2023-01-22T15:16:52.554751Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 8
2023-01-22T15:16:52.554784Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::8
2023-01-22T15:16:52.554794Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.554800Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.554806Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.555473Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1943968,
    events_root: None,
}
2023-01-22T15:16:52.555502Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 9
2023-01-22T15:16:52.555525Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::9
2023-01-22T15:16:52.555532Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.555539Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.555545Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.556144Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1906567,
    events_root: None,
}
2023-01-22T15:16:52.556171Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 10
2023-01-22T15:16:52.556195Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::10
2023-01-22T15:16:52.556202Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.556208Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.556214Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.557828Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4233379,
    events_root: None,
}
2023-01-22T15:16:52.557864Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 11
2023-01-22T15:16:52.557889Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::11
2023-01-22T15:16:52.557896Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.557902Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.557908Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.558504Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1828927,
    events_root: None,
}
2023-01-22T15:16:52.558530Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 12
2023-01-22T15:16:52.558554Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::12
2023-01-22T15:16:52.558562Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.558568Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.558574Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.560199Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4258747,
    events_root: None,
}
2023-01-22T15:16:52.560236Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 13
2023-01-22T15:16:52.560259Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::13
2023-01-22T15:16:52.560266Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.560273Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.560279Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.560881Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1854295,
    events_root: None,
}
2023-01-22T15:16:52.560907Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 14
2023-01-22T15:16:52.560930Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::14
2023-01-22T15:16:52.560937Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.560944Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.560950Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.562560Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4270727,
    events_root: None,
}
2023-01-22T15:16:52.562597Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 15
2023-01-22T15:16:52.562623Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::15
2023-01-22T15:16:52.562633Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.562644Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.562654Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.563270Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1866275,
    events_root: None,
}
2023-01-22T15:16:52.563296Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 16
2023-01-22T15:16:52.563321Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::16
2023-01-22T15:16:52.563327Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.563334Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.563340Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.564942Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4273123,
    events_root: None,
}
2023-01-22T15:16:52.564979Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 17
2023-01-22T15:16:52.565002Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::17
2023-01-22T15:16:52.565009Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.565016Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.565022Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.565638Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1868671,
    events_root: None,
}
2023-01-22T15:16:52.565667Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 18
2023-01-22T15:16:52.565694Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::18
2023-01-22T15:16:52.565701Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.565708Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.565714Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.567840Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4258755,
    events_root: None,
}
2023-01-22T15:16:52.567884Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 19
2023-01-22T15:16:52.567916Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::19
2023-01-22T15:16:52.567923Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.567930Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.567936Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.568558Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1854303,
    events_root: None,
}
2023-01-22T15:16:52.568586Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 20
2023-01-22T15:16:52.568609Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::20
2023-01-22T15:16:52.568616Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.568624Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.568631Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.570231Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4236828,
    events_root: None,
}
2023-01-22T15:16:52.570267Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 21
2023-01-22T15:16:52.570291Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::21
2023-01-22T15:16:52.570298Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.570304Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.570310Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.570926Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1831217,
    events_root: None,
}
2023-01-22T15:16:52.570953Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 22
2023-01-22T15:16:52.570976Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::22
2023-01-22T15:16:52.570983Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.570989Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.570995Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.572594Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4262196,
    events_root: None,
}
2023-01-22T15:16:52.572630Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 23
2023-01-22T15:16:52.572654Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::23
2023-01-22T15:16:52.572662Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.572668Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.572674Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.573282Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1856585,
    events_root: None,
}
2023-01-22T15:16:52.573308Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 24
2023-01-22T15:16:52.573333Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::24
2023-01-22T15:16:52.573340Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.573346Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.573352Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.574964Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4274176,
    events_root: None,
}
2023-01-22T15:16:52.575002Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 25
2023-01-22T15:16:52.575025Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::25
2023-01-22T15:16:52.575033Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.575040Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.575046Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.575653Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1868565,
    events_root: None,
}
2023-01-22T15:16:52.575679Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 26
2023-01-22T15:16:52.575702Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::26
2023-01-22T15:16:52.575710Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.575717Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.575723Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.577319Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4276572,
    events_root: None,
}
2023-01-22T15:16:52.577355Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 27
2023-01-22T15:16:52.577379Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::27
2023-01-22T15:16:52.577386Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.577393Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.577398Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.578001Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1870961,
    events_root: None,
}
2023-01-22T15:16:52.578027Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 28
2023-01-22T15:16:52.578051Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::28
2023-01-22T15:16:52.578058Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.578065Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.578070Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.579673Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4262204,
    events_root: None,
}
2023-01-22T15:16:52.579710Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 29
2023-01-22T15:16:52.579734Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::29
2023-01-22T15:16:52.579742Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.579748Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.579754Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.580367Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1856593,
    events_root: None,
}
2023-01-22T15:16:52.580392Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 30
2023-01-22T15:16:52.580417Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::30
2023-01-22T15:16:52.580424Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.580431Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.580437Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.582138Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4739573,
    events_root: None,
}
2023-01-22T15:16:52.582175Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 31
2023-01-22T15:16:52.582199Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::31
2023-01-22T15:16:52.582206Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.582212Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.582218Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.582977Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2818071,
    events_root: None,
}
2023-01-22T15:16:52.583004Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 32
2023-01-22T15:16:52.583028Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::32
2023-01-22T15:16:52.583036Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.583042Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.583048Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.585020Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4780398,
    events_root: None,
}
2023-01-22T15:16:52.585093Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 33
2023-01-22T15:16:52.585145Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::33
2023-01-22T15:16:52.585159Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.585171Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.585181Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.586081Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2843439,
    events_root: None,
}
2023-01-22T15:16:52.586110Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 34
2023-01-22T15:16:52.586135Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::34
2023-01-22T15:16:52.586142Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.586150Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.586156Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.587927Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4792378,
    events_root: None,
}
2023-01-22T15:16:52.587963Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 35
2023-01-22T15:16:52.587988Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::35
2023-01-22T15:16:52.587994Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.588001Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.588007Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.588743Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2855419,
    events_root: None,
}
2023-01-22T15:16:52.588772Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 36
2023-01-22T15:16:52.588795Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::36
2023-01-22T15:16:52.588801Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.588808Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.588814Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.590472Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4794774,
    events_root: None,
}
2023-01-22T15:16:52.590509Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 37
2023-01-22T15:16:52.590532Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::37
2023-01-22T15:16:52.590539Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.590547Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.590553Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.591298Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2857815,
    events_root: None,
}
2023-01-22T15:16:52.591327Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 38
2023-01-22T15:16:52.591351Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::38
2023-01-22T15:16:52.591357Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.591364Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.591370Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.593035Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4780406,
    events_root: None,
}
2023-01-22T15:16:52.593072Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 39
2023-01-22T15:16:52.593096Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::39
2023-01-22T15:16:52.593103Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.593110Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.593116Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.593850Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2843447,
    events_root: None,
}
2023-01-22T15:16:52.593878Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 40
2023-01-22T15:16:52.593902Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::40
2023-01-22T15:16:52.593909Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.593916Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.593922Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.594997Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3888701,
    events_root: None,
}
2023-01-22T15:16:52.595029Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 41
2023-01-22T15:16:52.595053Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::41
2023-01-22T15:16:52.595061Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.595068Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.595073Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.596012Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3369197,
    events_root: None,
}
2023-01-22T15:16:52.596043Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 42
2023-01-22T15:16:52.596066Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::42
2023-01-22T15:16:52.596073Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.596079Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.596086Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.597132Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3830685,
    events_root: None,
}
2023-01-22T15:16:52.597166Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 43
2023-01-22T15:16:52.597190Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::43
2023-01-22T15:16:52.597197Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.597204Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.597210Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.598119Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394565,
    events_root: None,
}
2023-01-22T15:16:52.598149Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 44
2023-01-22T15:16:52.598173Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::44
2023-01-22T15:16:52.598180Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.598187Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.598193Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.599257Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3842665,
    events_root: None,
}
2023-01-22T15:16:52.599291Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 45
2023-01-22T15:16:52.599314Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::45
2023-01-22T15:16:52.599322Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.599329Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.599335Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.600251Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3406545,
    events_root: None,
}
2023-01-22T15:16:52.600281Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 46
2023-01-22T15:16:52.600304Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::46
2023-01-22T15:16:52.600312Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.600319Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.600325Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.601548Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3845061,
    events_root: None,
}
2023-01-22T15:16:52.601593Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 47
2023-01-22T15:16:52.601633Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::47
2023-01-22T15:16:52.601645Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.601656Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.601665Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.602853Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3408941,
    events_root: None,
}
2023-01-22T15:16:52.602887Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 48
2023-01-22T15:16:52.602913Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::48
2023-01-22T15:16:52.602920Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.602927Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.602934Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.604010Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3830693,
    events_root: None,
}
2023-01-22T15:16:52.604045Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 49
2023-01-22T15:16:52.604068Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::49
2023-01-22T15:16:52.604074Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.604082Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.604088Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.604997Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394573,
    events_root: None,
}
2023-01-22T15:16:52.605027Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 50
2023-01-22T15:16:52.605050Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::50
2023-01-22T15:16:52.605058Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.605064Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.605071Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.605870Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3495633,
    events_root: None,
}
2023-01-22T15:16:52.605898Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 51
2023-01-22T15:16:52.605923Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::51
2023-01-22T15:16:52.605930Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.605936Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.605942Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.606840Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3369677,
    events_root: None,
}
2023-01-22T15:16:52.606870Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 52
2023-01-22T15:16:52.606894Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::52
2023-01-22T15:16:52.606902Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.606909Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.606915Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.607722Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3521001,
    events_root: None,
}
2023-01-22T15:16:52.607751Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 53
2023-01-22T15:16:52.607775Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::53
2023-01-22T15:16:52.607782Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.607788Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.607794Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.608694Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3395045,
    events_root: None,
}
2023-01-22T15:16:52.608724Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 54
2023-01-22T15:16:52.608748Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::54
2023-01-22T15:16:52.608755Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.608761Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.608767Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.609576Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3532981,
    events_root: None,
}
2023-01-22T15:16:52.609605Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 55
2023-01-22T15:16:52.609628Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::55
2023-01-22T15:16:52.609635Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.609642Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.609648Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.610558Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3407025,
    events_root: None,
}
2023-01-22T15:16:52.610588Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 56
2023-01-22T15:16:52.610612Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::56
2023-01-22T15:16:52.610619Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.610626Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.610632Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.611433Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3535377,
    events_root: None,
}
2023-01-22T15:16:52.611467Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 57
2023-01-22T15:16:52.611491Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::57
2023-01-22T15:16:52.611498Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.611504Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.611510Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.612444Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3409421,
    events_root: None,
}
2023-01-22T15:16:52.612476Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 58
2023-01-22T15:16:52.612499Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::58
2023-01-22T15:16:52.612507Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.612514Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.612520Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.613322Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3521009,
    events_root: None,
}
2023-01-22T15:16:52.613352Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 59
2023-01-22T15:16:52.613377Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::59
2023-01-22T15:16:52.613383Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.613390Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.613396Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.614301Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3395053,
    events_root: None,
}
2023-01-22T15:16:52.614331Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 60
2023-01-22T15:16:52.614356Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::60
2023-01-22T15:16:52.614362Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.614369Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.614375Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.616295Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5691229,
    events_root: None,
}
2023-01-22T15:16:52.616335Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 61
2023-01-22T15:16:52.616359Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::61
2023-01-22T15:16:52.616366Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.616373Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.616379Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.617287Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3368973,
    events_root: None,
}
2023-01-22T15:16:52.617317Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 62
2023-01-22T15:16:52.617341Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::62
2023-01-22T15:16:52.617348Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.617354Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.617360Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.619260Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5716597,
    events_root: None,
}
2023-01-22T15:16:52.619301Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 63
2023-01-22T15:16:52.619324Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::63
2023-01-22T15:16:52.619330Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.619337Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.619344Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.620531Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394341,
    events_root: None,
}
2023-01-22T15:16:52.620574Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 64
2023-01-22T15:16:52.620610Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::64
2023-01-22T15:16:52.620617Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.620625Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.620632Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.622747Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5728577,
    events_root: None,
}
2023-01-22T15:16:52.622791Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 65
2023-01-22T15:16:52.622819Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::65
2023-01-22T15:16:52.622826Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.622833Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.622839Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.623782Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3406321,
    events_root: None,
}
2023-01-22T15:16:52.623814Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 66
2023-01-22T15:16:52.623836Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::66
2023-01-22T15:16:52.623844Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.623850Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.623857Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.625751Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5730973,
    events_root: None,
}
2023-01-22T15:16:52.625791Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 67
2023-01-22T15:16:52.625815Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::67
2023-01-22T15:16:52.625823Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.625829Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.625835Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.626741Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3408717,
    events_root: None,
}
2023-01-22T15:16:52.626771Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 68
2023-01-22T15:16:52.626794Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::68
2023-01-22T15:16:52.626802Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.626809Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.626815Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.628713Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5716605,
    events_root: None,
}
2023-01-22T15:16:52.628754Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 69
2023-01-22T15:16:52.628777Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::69
2023-01-22T15:16:52.628784Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.628791Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.628797Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.629703Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394349,
    events_root: None,
}
2023-01-22T15:16:52.629734Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 70
2023-01-22T15:16:52.629757Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::70
2023-01-22T15:16:52.629764Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.629771Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.629777Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.630781Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3759123,
    events_root: None,
}
2023-01-22T15:16:52.630814Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 71
2023-01-22T15:16:52.630837Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::71
2023-01-22T15:16:52.630844Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.630851Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.630857Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.631768Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3368733,
    events_root: None,
}
2023-01-22T15:16:52.631799Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 72
2023-01-22T15:16:52.631823Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::72
2023-01-22T15:16:52.631830Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.631836Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.631842Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.632857Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3784491,
    events_root: None,
}
2023-01-22T15:16:52.632889Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 73
2023-01-22T15:16:52.632914Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::73
2023-01-22T15:16:52.632922Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.632929Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.632937Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.633852Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394101,
    events_root: None,
}
2023-01-22T15:16:52.633886Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 74
2023-01-22T15:16:52.633909Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::74
2023-01-22T15:16:52.633916Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.633922Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.633929Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.634955Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3796471,
    events_root: None,
}
2023-01-22T15:16:52.634991Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 75
2023-01-22T15:16:52.635014Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::75
2023-01-22T15:16:52.635021Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.635029Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.635035Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.635947Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3406081,
    events_root: None,
}
2023-01-22T15:16:52.635978Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 76
2023-01-22T15:16:52.636001Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::76
2023-01-22T15:16:52.636011Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.636021Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.636029Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.637186Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3798867,
    events_root: None,
}
2023-01-22T15:16:52.637246Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 77
2023-01-22T15:16:52.637288Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::77
2023-01-22T15:16:52.637302Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.637313Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.637322Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.638486Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3408477,
    events_root: None,
}
2023-01-22T15:16:52.638521Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 78
2023-01-22T15:16:52.638548Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::78
2023-01-22T15:16:52.638555Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.638562Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.638570Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.639636Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3784499,
    events_root: None,
}
2023-01-22T15:16:52.639671Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 79
2023-01-22T15:16:52.639695Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::79
2023-01-22T15:16:52.639701Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.639708Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.639714Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.640617Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394109,
    events_root: None,
}
2023-01-22T15:16:52.640647Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 80
2023-01-22T15:16:52.640671Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::80
2023-01-22T15:16:52.640678Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.640685Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.640691Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.643450Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6760163,
    events_root: None,
}
2023-01-22T15:16:52.643510Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 81
2023-01-22T15:16:52.643535Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::81
2023-01-22T15:16:52.643541Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.643548Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.643554Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.645453Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5132233,
    events_root: None,
}
2023-01-22T15:16:52.645499Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 82
2023-01-22T15:16:52.645522Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::82
2023-01-22T15:16:52.645529Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.645537Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.645543Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.647325Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4203826,
    events_root: None,
}
2023-01-22T15:16:52.647369Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 83
2023-01-22T15:16:52.647392Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::83
2023-01-22T15:16:52.647399Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.647406Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.647412Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.649218Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4206222,
    events_root: None,
}
2023-01-22T15:16:52.649261Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 84
2023-01-22T15:16:52.649284Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::84
2023-01-22T15:16:52.649291Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.649298Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.649304Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.651119Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4191854,
    events_root: None,
}
2023-01-22T15:16:52.651166Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-22T15:16:52.651189Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::0
2023-01-22T15:16:52.651195Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.651203Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.651209Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.652013Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2864889,
    events_root: None,
}
2023-01-22T15:16:52.652042Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-22T15:16:52.652066Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::1
2023-01-22T15:16:52.652073Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.652080Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.652086Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.652843Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2801386,
    events_root: None,
}
2023-01-22T15:16:52.652872Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-22T15:16:52.652895Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::2
2023-01-22T15:16:52.652902Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.652910Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.652916Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.653755Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2874617,
    events_root: None,
}
2023-01-22T15:16:52.653786Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-22T15:16:52.653811Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::3
2023-01-22T15:16:52.653817Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.653825Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.653831Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.654681Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2826754,
    events_root: None,
}
2023-01-22T15:16:52.654718Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-22T15:16:52.654748Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::4
2023-01-22T15:16:52.654756Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.654763Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.654771Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.655691Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2886597,
    events_root: None,
}
2023-01-22T15:16:52.655723Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-22T15:16:52.655750Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::5
2023-01-22T15:16:52.655756Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.655763Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.655769Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.656518Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2838734,
    events_root: None,
}
2023-01-22T15:16:52.656547Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 6
2023-01-22T15:16:52.656570Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::6
2023-01-22T15:16:52.656577Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.656585Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.656591Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.657394Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2888993,
    events_root: None,
}
2023-01-22T15:16:52.657422Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 7
2023-01-22T15:16:52.657447Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::7
2023-01-22T15:16:52.657454Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.657461Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.657467Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.658204Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2841130,
    events_root: None,
}
2023-01-22T15:16:52.658233Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 8
2023-01-22T15:16:52.658256Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::8
2023-01-22T15:16:52.658262Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.658269Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.658275Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.659080Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2874625,
    events_root: None,
}
2023-01-22T15:16:52.659110Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 9
2023-01-22T15:16:52.659134Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::9
2023-01-22T15:16:52.659141Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.659148Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.659154Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.659895Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2826762,
    events_root: None,
}
2023-01-22T15:16:52.659923Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 10
2023-01-22T15:16:52.659947Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::10
2023-01-22T15:16:52.659954Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.659961Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.659968Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.661596Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4233379,
    events_root: None,
}
2023-01-22T15:16:52.661633Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 11
2023-01-22T15:16:52.661660Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::11
2023-01-22T15:16:52.661667Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.661673Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.661679Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.662279Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1828927,
    events_root: None,
}
2023-01-22T15:16:52.662305Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 12
2023-01-22T15:16:52.662330Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::12
2023-01-22T15:16:52.662340Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.662349Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.662355Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.664014Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4258747,
    events_root: None,
}
2023-01-22T15:16:52.664059Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 13
2023-01-22T15:16:52.664090Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::13
2023-01-22T15:16:52.664097Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.664104Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.664109Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.664717Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1854295,
    events_root: None,
}
2023-01-22T15:16:52.664742Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 14
2023-01-22T15:16:52.664767Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::14
2023-01-22T15:16:52.664773Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.664780Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.664786Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.666448Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4270727,
    events_root: None,
}
2023-01-22T15:16:52.666494Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 15
2023-01-22T15:16:52.666521Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::15
2023-01-22T15:16:52.666529Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.666536Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.666542Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.667182Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1866275,
    events_root: None,
}
2023-01-22T15:16:52.667210Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 16
2023-01-22T15:16:52.667234Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::16
2023-01-22T15:16:52.667241Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.667247Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.667254Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.669017Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4273123,
    events_root: None,
}
2023-01-22T15:16:52.669072Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 17
2023-01-22T15:16:52.669110Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::17
2023-01-22T15:16:52.669121Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.669131Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.669140Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.669928Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1868671,
    events_root: None,
}
2023-01-22T15:16:52.669964Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 18
2023-01-22T15:16:52.669996Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::18
2023-01-22T15:16:52.670006Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.670017Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.670025Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.671998Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4258755,
    events_root: None,
}
2023-01-22T15:16:52.672048Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 19
2023-01-22T15:16:52.672080Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::19
2023-01-22T15:16:52.672090Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.672100Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.672108Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.672857Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1854303,
    events_root: None,
}
2023-01-22T15:16:52.672910Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 20
2023-01-22T15:16:52.672945Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::20
2023-01-22T15:16:52.672955Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.672965Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.672973Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.675054Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4236828,
    events_root: None,
}
2023-01-22T15:16:52.675109Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 21
2023-01-22T15:16:52.675148Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::21
2023-01-22T15:16:52.675155Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.675163Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.675169Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.675814Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1831217,
    events_root: None,
}
2023-01-22T15:16:52.675850Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 22
2023-01-22T15:16:52.675884Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::22
2023-01-22T15:16:52.675895Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.675905Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.675914Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.677963Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4262196,
    events_root: None,
}
2023-01-22T15:16:52.678001Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 23
2023-01-22T15:16:52.678029Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::23
2023-01-22T15:16:52.678037Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.678045Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.678051Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.678659Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1856585,
    events_root: None,
}
2023-01-22T15:16:52.678687Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 24
2023-01-22T15:16:52.678710Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::24
2023-01-22T15:16:52.678717Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.678723Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.678730Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.680378Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4274176,
    events_root: None,
}
2023-01-22T15:16:52.680415Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 25
2023-01-22T15:16:52.680439Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::25
2023-01-22T15:16:52.680446Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.680453Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.680459Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.681068Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1868565,
    events_root: None,
}
2023-01-22T15:16:52.681094Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 26
2023-01-22T15:16:52.681119Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::26
2023-01-22T15:16:52.681126Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.681132Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.681138Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.682895Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4276572,
    events_root: None,
}
2023-01-22T15:16:52.682932Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 27
2023-01-22T15:16:52.682957Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::27
2023-01-22T15:16:52.682964Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.682970Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.682976Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.683621Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1870961,
    events_root: None,
}
2023-01-22T15:16:52.683647Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 28
2023-01-22T15:16:52.683671Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::28
2023-01-22T15:16:52.683677Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.683685Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.683691Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.685414Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4262204,
    events_root: None,
}
2023-01-22T15:16:52.685453Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 29
2023-01-22T15:16:52.685476Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::29
2023-01-22T15:16:52.685483Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.685490Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.685496Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.686114Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1856593,
    events_root: None,
}
2023-01-22T15:16:52.686141Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 30
2023-01-22T15:16:52.686164Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::30
2023-01-22T15:16:52.686171Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.686178Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.686185Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.687882Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4739573,
    events_root: None,
}
2023-01-22T15:16:52.687919Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 31
2023-01-22T15:16:52.687943Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::31
2023-01-22T15:16:52.687950Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.687957Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.687963Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.688706Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2818071,
    events_root: None,
}
2023-01-22T15:16:52.688734Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 32
2023-01-22T15:16:52.688759Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::32
2023-01-22T15:16:52.688766Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.688773Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.688778Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.690513Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4780398,
    events_root: None,
}
2023-01-22T15:16:52.690571Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 33
2023-01-22T15:16:52.690609Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::33
2023-01-22T15:16:52.690619Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.690628Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.690636Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.691690Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2843439,
    events_root: None,
}
2023-01-22T15:16:52.691738Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 34
2023-01-22T15:16:52.691778Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::34
2023-01-22T15:16:52.691789Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.691800Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.691809Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.693777Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4792378,
    events_root: None,
}
2023-01-22T15:16:52.693831Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 35
2023-01-22T15:16:52.693867Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::35
2023-01-22T15:16:52.693879Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.693889Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.693898Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.694869Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2855419,
    events_root: None,
}
2023-01-22T15:16:52.694906Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 36
2023-01-22T15:16:52.694939Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::36
2023-01-22T15:16:52.694950Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.694960Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.694968Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.697080Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4794774,
    events_root: None,
}
2023-01-22T15:16:52.697129Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 37
2023-01-22T15:16:52.697160Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::37
2023-01-22T15:16:52.697170Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.697180Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.697189Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.698111Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2857815,
    events_root: None,
}
2023-01-22T15:16:52.698149Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 38
2023-01-22T15:16:52.698179Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::38
2023-01-22T15:16:52.698189Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.698198Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.698208Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.700275Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4780406,
    events_root: None,
}
2023-01-22T15:16:52.700319Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 39
2023-01-22T15:16:52.700345Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::39
2023-01-22T15:16:52.700352Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.700359Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.700365Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.701109Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2843447,
    events_root: None,
}
2023-01-22T15:16:52.701138Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 40
2023-01-22T15:16:52.701162Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::40
2023-01-22T15:16:52.701169Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.701176Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.701182Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.702269Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3888701,
    events_root: None,
}
2023-01-22T15:16:52.702303Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 41
2023-01-22T15:16:52.702326Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::41
2023-01-22T15:16:52.702333Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.702340Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.702346Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.703332Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3369197,
    events_root: None,
}
2023-01-22T15:16:52.703374Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 42
2023-01-22T15:16:52.703407Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::42
2023-01-22T15:16:52.703417Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.703427Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.703435Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.704577Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3830685,
    events_root: None,
}
2023-01-22T15:16:52.704622Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 43
2023-01-22T15:16:52.704647Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::43
2023-01-22T15:16:52.704654Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.704660Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.704667Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.705586Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394565,
    events_root: None,
}
2023-01-22T15:16:52.705616Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 44
2023-01-22T15:16:52.705639Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::44
2023-01-22T15:16:52.705647Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.705655Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.705661Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.706713Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3842665,
    events_root: None,
}
2023-01-22T15:16:52.706746Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 45
2023-01-22T15:16:52.706770Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::45
2023-01-22T15:16:52.706776Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.706783Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.706789Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.707698Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3406545,
    events_root: None,
}
2023-01-22T15:16:52.707729Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 46
2023-01-22T15:16:52.707752Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::46
2023-01-22T15:16:52.707759Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.707766Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.707772Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.708837Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3845061,
    events_root: None,
}
2023-01-22T15:16:52.708873Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 47
2023-01-22T15:16:52.708901Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::47
2023-01-22T15:16:52.708907Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.708914Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.708920Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.709951Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3408941,
    events_root: None,
}
2023-01-22T15:16:52.709990Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 48
2023-01-22T15:16:52.710024Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::48
2023-01-22T15:16:52.710032Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.710041Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.710047Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.711189Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3830693,
    events_root: None,
}
2023-01-22T15:16:52.711224Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 49
2023-01-22T15:16:52.711248Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::49
2023-01-22T15:16:52.711255Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.711263Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.711269Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.712188Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394573,
    events_root: None,
}
2023-01-22T15:16:52.712218Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 50
2023-01-22T15:16:52.712242Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::50
2023-01-22T15:16:52.712250Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.712256Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.712262Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.713060Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3495633,
    events_root: None,
}
2023-01-22T15:16:52.713088Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 51
2023-01-22T15:16:52.713113Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::51
2023-01-22T15:16:52.713119Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.713126Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.713132Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.714033Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3369677,
    events_root: None,
}
2023-01-22T15:16:52.714062Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 52
2023-01-22T15:16:52.714087Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::52
2023-01-22T15:16:52.714094Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.714101Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.714107Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.714905Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3521001,
    events_root: None,
}
2023-01-22T15:16:52.714934Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 53
2023-01-22T15:16:52.714957Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::53
2023-01-22T15:16:52.714964Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.714971Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.714977Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.715881Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3395045,
    events_root: None,
}
2023-01-22T15:16:52.715913Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 54
2023-01-22T15:16:52.715935Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::54
2023-01-22T15:16:52.715942Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.715949Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.715955Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.716757Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3532981,
    events_root: None,
}
2023-01-22T15:16:52.716786Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 55
2023-01-22T15:16:52.716809Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::55
2023-01-22T15:16:52.716817Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.716824Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.716830Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.717735Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3407025,
    events_root: None,
}
2023-01-22T15:16:52.717765Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 56
2023-01-22T15:16:52.717789Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::56
2023-01-22T15:16:52.717796Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.717803Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.717809Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.718619Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3535377,
    events_root: None,
}
2023-01-22T15:16:52.718648Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 57
2023-01-22T15:16:52.718672Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::57
2023-01-22T15:16:52.718679Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.718686Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.718691Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.719604Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3409421,
    events_root: None,
}
2023-01-22T15:16:52.719635Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 58
2023-01-22T15:16:52.719658Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::58
2023-01-22T15:16:52.719664Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.719671Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.719677Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.720487Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3521009,
    events_root: None,
}
2023-01-22T15:16:52.720515Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 59
2023-01-22T15:16:52.720539Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::59
2023-01-22T15:16:52.720547Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.720554Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.720560Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.721469Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3395053,
    events_root: None,
}
2023-01-22T15:16:52.721499Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 60
2023-01-22T15:16:52.721524Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::60
2023-01-22T15:16:52.721531Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.721537Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.721543Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.723457Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5691229,
    events_root: None,
}
2023-01-22T15:16:52.723513Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 61
2023-01-22T15:16:52.723538Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::61
2023-01-22T15:16:52.723544Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.723551Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.723557Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.724464Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3368973,
    events_root: None,
}
2023-01-22T15:16:52.724493Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 62
2023-01-22T15:16:52.724518Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::62
2023-01-22T15:16:52.724525Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.724532Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.724537Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.726435Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5716597,
    events_root: None,
}
2023-01-22T15:16:52.726476Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 63
2023-01-22T15:16:52.726499Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::63
2023-01-22T15:16:52.726506Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.726513Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.726520Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.727468Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394341,
    events_root: None,
}
2023-01-22T15:16:52.727510Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 64
2023-01-22T15:16:52.727538Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::64
2023-01-22T15:16:52.727545Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.727552Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.727559Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.729633Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5728577,
    events_root: None,
}
2023-01-22T15:16:52.729680Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 65
2023-01-22T15:16:52.729709Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::65
2023-01-22T15:16:52.729717Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.729723Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.729729Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.730661Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3406321,
    events_root: None,
}
2023-01-22T15:16:52.730692Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 66
2023-01-22T15:16:52.730715Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::66
2023-01-22T15:16:52.730722Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.730730Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.730736Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.732628Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5730973,
    events_root: None,
}
2023-01-22T15:16:52.732668Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 67
2023-01-22T15:16:52.732692Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::67
2023-01-22T15:16:52.732699Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.732706Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.732712Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.733629Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3408717,
    events_root: None,
}
2023-01-22T15:16:52.733660Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 68
2023-01-22T15:16:52.733684Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::68
2023-01-22T15:16:52.733691Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.733697Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.733703Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.735604Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5716605,
    events_root: None,
}
2023-01-22T15:16:52.735645Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 69
2023-01-22T15:16:52.735669Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::69
2023-01-22T15:16:52.735676Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.735684Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.735690Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.736596Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394349,
    events_root: None,
}
2023-01-22T15:16:52.736627Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 70
2023-01-22T15:16:52.736650Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::70
2023-01-22T15:16:52.736657Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.736665Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.736670Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.737678Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3759123,
    events_root: None,
}
2023-01-22T15:16:52.737711Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 71
2023-01-22T15:16:52.737734Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::71
2023-01-22T15:16:52.737741Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.737748Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.737754Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.738651Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3368733,
    events_root: None,
}
2023-01-22T15:16:52.738683Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 72
2023-01-22T15:16:52.738706Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::72
2023-01-22T15:16:52.738712Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.738719Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.738726Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.739754Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3784491,
    events_root: None,
}
2023-01-22T15:16:52.739788Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 73
2023-01-22T15:16:52.739811Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::73
2023-01-22T15:16:52.739818Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.739826Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.739833Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.740746Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394101,
    events_root: None,
}
2023-01-22T15:16:52.740777Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 74
2023-01-22T15:16:52.740800Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::74
2023-01-22T15:16:52.740807Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.740815Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.740821Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.741833Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3796471,
    events_root: None,
}
2023-01-22T15:16:52.741867Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 75
2023-01-22T15:16:52.741889Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::75
2023-01-22T15:16:52.741896Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.741904Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.741910Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.742811Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3406081,
    events_root: None,
}
2023-01-22T15:16:52.742842Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 76
2023-01-22T15:16:52.742865Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::76
2023-01-22T15:16:52.742872Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.742879Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.742886Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.743906Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3798867,
    events_root: None,
}
2023-01-22T15:16:52.743939Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 77
2023-01-22T15:16:52.743962Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::77
2023-01-22T15:16:52.743969Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.743977Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.743983Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.744885Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3408477,
    events_root: None,
}
2023-01-22T15:16:52.744916Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 78
2023-01-22T15:16:52.744939Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::78
2023-01-22T15:16:52.744946Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.744953Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.744960Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.745966Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3784499,
    events_root: None,
}
2023-01-22T15:16:52.746000Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 79
2023-01-22T15:16:52.746023Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::79
2023-01-22T15:16:52.746030Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.746036Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.746042Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.746958Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394109,
    events_root: None,
}
2023-01-22T15:16:52.746990Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 80
2023-01-22T15:16:52.747013Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::80
2023-01-22T15:16:52.747020Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.747030Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.747040Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.749448Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5106865,
    events_root: None,
}
2023-01-22T15:16:52.749511Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 81
2023-01-22T15:16:52.749548Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::81
2023-01-22T15:16:52.749555Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.749562Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.749568Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.751385Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4191846,
    events_root: None,
}
2023-01-22T15:16:52.751428Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 82
2023-01-22T15:16:52.751452Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::82
2023-01-22T15:16:52.751458Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.751474Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.751480Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.753220Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4203826,
    events_root: None,
}
2023-01-22T15:16:52.753264Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 83
2023-01-22T15:16:52.753287Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::83
2023-01-22T15:16:52.753293Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.753300Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.753306Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.755040Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4206222,
    events_root: None,
}
2023-01-22T15:16:52.755083Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 84
2023-01-22T15:16:52.755107Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::84
2023-01-22T15:16:52.755115Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.755122Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.755128Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.756859Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4191854,
    events_root: None,
}
2023-01-22T15:16:52.756904Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-22T15:16:52.756927Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::0
2023-01-22T15:16:52.756934Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.756941Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.756947Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.757724Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2864889,
    events_root: None,
}
2023-01-22T15:16:52.757752Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-22T15:16:52.757776Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::1
2023-01-22T15:16:52.757783Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.757789Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.757795Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.758511Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2801386,
    events_root: None,
}
2023-01-22T15:16:52.758539Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-22T15:16:52.758561Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::2
2023-01-22T15:16:52.758568Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.758575Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.758582Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.759356Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2874617,
    events_root: None,
}
2023-01-22T15:16:52.759385Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-22T15:16:52.759408Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::3
2023-01-22T15:16:52.759415Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.759421Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.759427Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.760151Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2826754,
    events_root: None,
}
2023-01-22T15:16:52.760180Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-22T15:16:52.760202Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::4
2023-01-22T15:16:52.760209Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.760216Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.760221Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.760995Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2886597,
    events_root: None,
}
2023-01-22T15:16:52.761024Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-22T15:16:52.761047Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::5
2023-01-22T15:16:52.761053Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.761060Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.761067Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.761792Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2838734,
    events_root: None,
}
2023-01-22T15:16:52.761819Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 6
2023-01-22T15:16:52.761843Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::6
2023-01-22T15:16:52.761850Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.761856Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.761862Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.762636Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2888993,
    events_root: None,
}
2023-01-22T15:16:52.762666Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 7
2023-01-22T15:16:52.762688Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::7
2023-01-22T15:16:52.762695Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.762702Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.762708Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.763424Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2841130,
    events_root: None,
}
2023-01-22T15:16:52.763451Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 8
2023-01-22T15:16:52.763479Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::8
2023-01-22T15:16:52.763488Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.763494Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.763500Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.764273Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2874625,
    events_root: None,
}
2023-01-22T15:16:52.764301Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 9
2023-01-22T15:16:52.764325Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::9
2023-01-22T15:16:52.764332Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.764338Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.764344Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.765060Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2826762,
    events_root: None,
}
2023-01-22T15:16:52.765088Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 10
2023-01-22T15:16:52.765111Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::10
2023-01-22T15:16:52.765118Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.765124Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.765130Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.766678Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4233379,
    events_root: None,
}
2023-01-22T15:16:52.766714Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 11
2023-01-22T15:16:52.766738Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::11
2023-01-22T15:16:52.766744Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.766751Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.766757Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.767340Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1828927,
    events_root: None,
}
2023-01-22T15:16:52.767366Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 12
2023-01-22T15:16:52.767389Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::12
2023-01-22T15:16:52.767396Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.767403Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.767408Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.769111Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4258747,
    events_root: None,
}
2023-01-22T15:16:52.769166Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 13
2023-01-22T15:16:52.769204Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::13
2023-01-22T15:16:52.769216Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.769226Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.769234Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.769965Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1854295,
    events_root: None,
}
2023-01-22T15:16:52.769994Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 14
2023-01-22T15:16:52.770019Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::14
2023-01-22T15:16:52.770026Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.770033Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.770039Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.771661Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4270727,
    events_root: None,
}
2023-01-22T15:16:52.771698Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 15
2023-01-22T15:16:52.771722Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::15
2023-01-22T15:16:52.771729Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.771736Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.771742Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.772330Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1866275,
    events_root: None,
}
2023-01-22T15:16:52.772357Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 16
2023-01-22T15:16:52.772379Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::16
2023-01-22T15:16:52.772386Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.772393Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.772398Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.773955Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4273123,
    events_root: None,
}
2023-01-22T15:16:52.773991Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 17
2023-01-22T15:16:52.774014Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::17
2023-01-22T15:16:52.774021Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.774028Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.774034Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.774626Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1868671,
    events_root: None,
}
2023-01-22T15:16:52.774652Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 18
2023-01-22T15:16:52.774675Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::18
2023-01-22T15:16:52.774682Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.774688Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.774694Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.776254Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4258755,
    events_root: None,
}
2023-01-22T15:16:52.776290Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 19
2023-01-22T15:16:52.776314Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::19
2023-01-22T15:16:52.776320Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.776327Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.776333Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.776913Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1854303,
    events_root: None,
}
2023-01-22T15:16:52.776940Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 20
2023-01-22T15:16:52.776962Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::20
2023-01-22T15:16:52.776969Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.776976Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.776982Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.778526Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4236828,
    events_root: None,
}
2023-01-22T15:16:52.778561Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 21
2023-01-22T15:16:52.778584Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::21
2023-01-22T15:16:52.778591Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.778598Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.778604Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.779181Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1831217,
    events_root: None,
}
2023-01-22T15:16:52.779207Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 22
2023-01-22T15:16:52.779230Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::22
2023-01-22T15:16:52.779237Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.779244Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.779250Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.780804Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4262196,
    events_root: None,
}
2023-01-22T15:16:52.780841Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 23
2023-01-22T15:16:52.780863Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::23
2023-01-22T15:16:52.780870Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.780877Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.780883Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.781477Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1856585,
    events_root: None,
}
2023-01-22T15:16:52.781503Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 24
2023-01-22T15:16:52.781527Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::24
2023-01-22T15:16:52.781534Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.781540Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.781546Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.783212Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4274176,
    events_root: None,
}
2023-01-22T15:16:52.783263Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 25
2023-01-22T15:16:52.783298Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::25
2023-01-22T15:16:52.783308Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.783317Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.783326Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.784125Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1868565,
    events_root: None,
}
2023-01-22T15:16:52.784155Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 26
2023-01-22T15:16:52.784182Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::26
2023-01-22T15:16:52.784190Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.784197Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.784205Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.785808Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4276572,
    events_root: None,
}
2023-01-22T15:16:52.785844Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 27
2023-01-22T15:16:52.785868Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::27
2023-01-22T15:16:52.785875Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.785882Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.785888Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.786477Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1870961,
    events_root: None,
}
2023-01-22T15:16:52.786503Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 28
2023-01-22T15:16:52.786526Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::28
2023-01-22T15:16:52.786533Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.786540Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.786545Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.788116Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4262204,
    events_root: None,
}
2023-01-22T15:16:52.788153Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 29
2023-01-22T15:16:52.788176Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::29
2023-01-22T15:16:52.788183Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.788189Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.788195Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.788782Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1856593,
    events_root: None,
}
2023-01-22T15:16:52.788808Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 30
2023-01-22T15:16:52.788831Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::30
2023-01-22T15:16:52.788837Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.788845Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.788851Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.790496Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4739573,
    events_root: None,
}
2023-01-22T15:16:52.790533Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 31
2023-01-22T15:16:52.790556Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::31
2023-01-22T15:16:52.790563Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.790570Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.790576Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.791298Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2818071,
    events_root: None,
}
2023-01-22T15:16:52.791325Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 32
2023-01-22T15:16:52.791349Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::32
2023-01-22T15:16:52.791356Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.791362Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.791368Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.793009Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4780398,
    events_root: None,
}
2023-01-22T15:16:52.793044Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 33
2023-01-22T15:16:52.793069Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::33
2023-01-22T15:16:52.793075Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.793082Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.793088Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.793814Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2843439,
    events_root: None,
}
2023-01-22T15:16:52.793842Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 34
2023-01-22T15:16:52.793864Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::34
2023-01-22T15:16:52.793871Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.793879Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.793885Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.795518Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4792378,
    events_root: None,
}
2023-01-22T15:16:52.795554Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 35
2023-01-22T15:16:52.795577Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::35
2023-01-22T15:16:52.795584Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.795590Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.795597Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.796324Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2855419,
    events_root: None,
}
2023-01-22T15:16:52.796351Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 36
2023-01-22T15:16:52.796375Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::36
2023-01-22T15:16:52.796382Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.796388Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.796394Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.798017Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4794774,
    events_root: None,
}
2023-01-22T15:16:52.798053Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 37
2023-01-22T15:16:52.798076Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::37
2023-01-22T15:16:52.798084Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.798090Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.798096Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.798817Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2857815,
    events_root: None,
}
2023-01-22T15:16:52.798845Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 38
2023-01-22T15:16:52.798869Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::38
2023-01-22T15:16:52.798875Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.798882Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.798888Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.800537Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4780406,
    events_root: None,
}
2023-01-22T15:16:52.800575Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 39
2023-01-22T15:16:52.800598Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::39
2023-01-22T15:16:52.800604Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.800611Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.800617Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.801339Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2843447,
    events_root: None,
}
2023-01-22T15:16:52.801367Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 40
2023-01-22T15:16:52.801389Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::40
2023-01-22T15:16:52.801397Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.801404Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.801410Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.802444Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3888701,
    events_root: None,
}
2023-01-22T15:16:52.802477Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 41
2023-01-22T15:16:52.802500Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::41
2023-01-22T15:16:52.802510Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.802520Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.802529Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.803770Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3369197,
    events_root: None,
}
2023-01-22T15:16:52.803816Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 42
2023-01-22T15:16:52.803851Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::42
2023-01-22T15:16:52.803858Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.803865Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.803871Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.805017Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3830685,
    events_root: None,
}
2023-01-22T15:16:52.805052Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 43
2023-01-22T15:16:52.805077Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::43
2023-01-22T15:16:52.805083Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.805091Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.805097Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.805996Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394565,
    events_root: None,
}
2023-01-22T15:16:52.806025Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 44
2023-01-22T15:16:52.806049Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::44
2023-01-22T15:16:52.806056Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.806063Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.806068Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.807094Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3842665,
    events_root: None,
}
2023-01-22T15:16:52.807126Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 45
2023-01-22T15:16:52.807150Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::45
2023-01-22T15:16:52.807157Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.807163Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.807170Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.808067Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3406545,
    events_root: None,
}
2023-01-22T15:16:52.808097Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 46
2023-01-22T15:16:52.808120Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::46
2023-01-22T15:16:52.808127Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.808133Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.808139Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.809163Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3845061,
    events_root: None,
}
2023-01-22T15:16:52.809196Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 47
2023-01-22T15:16:52.809219Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::47
2023-01-22T15:16:52.809226Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.809234Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.809239Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.810128Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3408941,
    events_root: None,
}
2023-01-22T15:16:52.810158Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 48
2023-01-22T15:16:52.810181Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::48
2023-01-22T15:16:52.810188Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.810195Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.810201Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.811222Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3830693,
    events_root: None,
}
2023-01-22T15:16:52.811254Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 49
2023-01-22T15:16:52.811278Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::49
2023-01-22T15:16:52.811285Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.811292Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.811297Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.812185Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394573,
    events_root: None,
}
2023-01-22T15:16:52.812217Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 50
2023-01-22T15:16:52.812241Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::50
2023-01-22T15:16:52.812247Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.812254Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.812260Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.813036Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3495633,
    events_root: None,
}
2023-01-22T15:16:52.813064Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 51
2023-01-22T15:16:52.813087Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::51
2023-01-22T15:16:52.813094Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.813100Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.813106Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.813997Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3369677,
    events_root: None,
}
2023-01-22T15:16:52.814037Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 52
2023-01-22T15:16:52.814066Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::52
2023-01-22T15:16:52.814074Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.814081Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.814086Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.814891Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3521001,
    events_root: None,
}
2023-01-22T15:16:52.814920Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 53
2023-01-22T15:16:52.814943Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::53
2023-01-22T15:16:52.814949Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.814956Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.814962Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.815855Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3395045,
    events_root: None,
}
2023-01-22T15:16:52.815885Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 54
2023-01-22T15:16:52.815908Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::54
2023-01-22T15:16:52.815915Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.815922Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.815928Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.816719Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3532981,
    events_root: None,
}
2023-01-22T15:16:52.816748Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 55
2023-01-22T15:16:52.816772Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::55
2023-01-22T15:16:52.816778Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.816785Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.816791Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.817679Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3407025,
    events_root: None,
}
2023-01-22T15:16:52.817709Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 56
2023-01-22T15:16:52.817732Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::56
2023-01-22T15:16:52.817739Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.817746Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.817752Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.818535Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3535377,
    events_root: None,
}
2023-01-22T15:16:52.818563Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 57
2023-01-22T15:16:52.818587Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::57
2023-01-22T15:16:52.818593Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.818600Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.818606Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.819493Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3409421,
    events_root: None,
}
2023-01-22T15:16:52.819523Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 58
2023-01-22T15:16:52.819546Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::58
2023-01-22T15:16:52.819553Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.819560Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.819566Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.820350Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3521009,
    events_root: None,
}
2023-01-22T15:16:52.820379Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 59
2023-01-22T15:16:52.820401Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::59
2023-01-22T15:16:52.820409Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.820416Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.820422Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.821302Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3395053,
    events_root: None,
}
2023-01-22T15:16:52.821332Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 60
2023-01-22T15:16:52.821355Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::60
2023-01-22T15:16:52.821362Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.821369Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.821375Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.823240Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5691229,
    events_root: None,
}
2023-01-22T15:16:52.823280Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 61
2023-01-22T15:16:52.823304Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::61
2023-01-22T15:16:52.823310Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.823317Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.823323Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.824567Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3368973,
    events_root: None,
}
2023-01-22T15:16:52.824618Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 62
2023-01-22T15:16:52.824655Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::62
2023-01-22T15:16:52.824662Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.824673Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.824682Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.826745Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5716597,
    events_root: None,
}
2023-01-22T15:16:52.826787Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 63
2023-01-22T15:16:52.826814Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::63
2023-01-22T15:16:52.826821Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.826828Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.826834Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.827742Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394341,
    events_root: None,
}
2023-01-22T15:16:52.827772Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 64
2023-01-22T15:16:52.827796Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::64
2023-01-22T15:16:52.827803Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.827809Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.827815Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.829670Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5728577,
    events_root: None,
}
2023-01-22T15:16:52.829710Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 65
2023-01-22T15:16:52.829733Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::65
2023-01-22T15:16:52.829739Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.829747Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.829753Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.830643Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3406321,
    events_root: None,
}
2023-01-22T15:16:52.830673Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 66
2023-01-22T15:16:52.830696Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::66
2023-01-22T15:16:52.830703Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.830709Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.830715Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.832571Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5730973,
    events_root: None,
}
2023-01-22T15:16:52.832611Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 67
2023-01-22T15:16:52.832634Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::67
2023-01-22T15:16:52.832641Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.832647Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.832653Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.833541Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3408717,
    events_root: None,
}
2023-01-22T15:16:52.833572Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 68
2023-01-22T15:16:52.833598Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::68
2023-01-22T15:16:52.833607Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.833616Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.833623Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.835506Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5716605,
    events_root: None,
}
2023-01-22T15:16:52.835546Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 69
2023-01-22T15:16:52.835569Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::69
2023-01-22T15:16:52.835576Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.835583Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.835589Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.836473Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394349,
    events_root: None,
}
2023-01-22T15:16:52.836503Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 70
2023-01-22T15:16:52.836526Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::70
2023-01-22T15:16:52.836533Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.836540Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.836546Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.837552Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3759123,
    events_root: None,
}
2023-01-22T15:16:52.837585Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 71
2023-01-22T15:16:52.837608Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::71
2023-01-22T15:16:52.837615Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.837622Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.837628Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.838509Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3368733,
    events_root: None,
}
2023-01-22T15:16:52.838550Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 72
2023-01-22T15:16:52.838583Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::72
2023-01-22T15:16:52.838595Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.838605Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.838614Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.839691Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3784491,
    events_root: None,
}
2023-01-22T15:16:52.839736Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 73
2023-01-22T15:16:52.839770Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::73
2023-01-22T15:16:52.839777Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.839784Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.839790Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.840821Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394101,
    events_root: None,
}
2023-01-22T15:16:52.840854Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 74
2023-01-22T15:16:52.840880Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::74
2023-01-22T15:16:52.840886Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.840893Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.840899Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.841904Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3796471,
    events_root: None,
}
2023-01-22T15:16:52.841937Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 75
2023-01-22T15:16:52.841961Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::75
2023-01-22T15:16:52.841967Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.841974Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.841980Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.842888Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3406081,
    events_root: None,
}
2023-01-22T15:16:52.842918Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 76
2023-01-22T15:16:52.842941Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::76
2023-01-22T15:16:52.842948Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.842954Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.842960Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.843960Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3798867,
    events_root: None,
}
2023-01-22T15:16:52.843993Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 77
2023-01-22T15:16:52.844016Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::77
2023-01-22T15:16:52.844022Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.844030Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.844036Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.844921Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3408477,
    events_root: None,
}
2023-01-22T15:16:52.844952Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 78
2023-01-22T15:16:52.844975Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::78
2023-01-22T15:16:52.844981Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.844988Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.844994Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.845984Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3784499,
    events_root: None,
}
2023-01-22T15:16:52.846016Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 79
2023-01-22T15:16:52.846039Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::79
2023-01-22T15:16:52.846046Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.846053Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.846058Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.846961Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394109,
    events_root: None,
}
2023-01-22T15:16:52.846991Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 80
2023-01-22T15:16:52.847014Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::80
2023-01-22T15:16:52.847022Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.847028Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.847034Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.848926Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5106865,
    events_root: None,
}
2023-01-22T15:16:52.848971Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 81
2023-01-22T15:16:52.848994Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::81
2023-01-22T15:16:52.849001Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.849008Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.849014Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.850773Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4191846,
    events_root: None,
}
2023-01-22T15:16:52.850816Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 82
2023-01-22T15:16:52.850839Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::82
2023-01-22T15:16:52.850846Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.850852Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.850858Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.852594Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4203826,
    events_root: None,
}
2023-01-22T15:16:52.852637Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 83
2023-01-22T15:16:52.852660Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::83
2023-01-22T15:16:52.852666Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.852673Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.852679Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.854404Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4206222,
    events_root: None,
}
2023-01-22T15:16:52.854445Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 84
2023-01-22T15:16:52.854469Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::84
2023-01-22T15:16:52.854476Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.854482Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.854488Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.856267Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4191854,
    events_root: None,
}
2023-01-22T15:16:52.856313Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-22T15:16:52.856337Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::0
2023-01-22T15:16:52.856345Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.856352Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.856360Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.857143Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2864889,
    events_root: None,
}
2023-01-22T15:16:52.857172Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-22T15:16:52.857195Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::1
2023-01-22T15:16:52.857202Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.857209Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.857215Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.857933Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2801386,
    events_root: None,
}
2023-01-22T15:16:52.857961Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-22T15:16:52.857984Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::2
2023-01-22T15:16:52.857991Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.857998Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.858004Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.858802Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2874617,
    events_root: None,
}
2023-01-22T15:16:52.858831Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-22T15:16:52.858854Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::3
2023-01-22T15:16:52.858862Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.858868Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.858874Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.859605Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2826754,
    events_root: None,
}
2023-01-22T15:16:52.859633Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-22T15:16:52.859657Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::4
2023-01-22T15:16:52.859663Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.859670Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.859676Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.860454Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2886597,
    events_root: None,
}
2023-01-22T15:16:52.860483Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-22T15:16:52.860506Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::5
2023-01-22T15:16:52.860513Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.860519Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.860525Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.861247Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2838734,
    events_root: None,
}
2023-01-22T15:16:52.861275Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-22T15:16:52.861298Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::6
2023-01-22T15:16:52.861305Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.861311Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.861317Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.862100Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2888993,
    events_root: None,
}
2023-01-22T15:16:52.862131Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-22T15:16:52.862162Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::7
2023-01-22T15:16:52.862173Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.862182Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.862188Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.863022Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2841130,
    events_root: None,
}
2023-01-22T15:16:52.863056Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 8
2023-01-22T15:16:52.863087Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::8
2023-01-22T15:16:52.863094Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.863101Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.863107Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.864031Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2874625,
    events_root: None,
}
2023-01-22T15:16:52.864068Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 9
2023-01-22T15:16:52.864095Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::9
2023-01-22T15:16:52.864102Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.864110Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.864116Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.864868Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2826762,
    events_root: None,
}
2023-01-22T15:16:52.864896Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 10
2023-01-22T15:16:52.864920Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::10
2023-01-22T15:16:52.864926Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.864933Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.864939Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.866517Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4233379,
    events_root: None,
}
2023-01-22T15:16:52.866554Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 11
2023-01-22T15:16:52.866577Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::11
2023-01-22T15:16:52.866584Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.866590Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.866596Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.867192Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1828927,
    events_root: None,
}
2023-01-22T15:16:52.867219Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 12
2023-01-22T15:16:52.867241Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::12
2023-01-22T15:16:52.867248Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.867255Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.867261Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.868829Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4258747,
    events_root: None,
}
2023-01-22T15:16:52.868865Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 13
2023-01-22T15:16:52.868888Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::13
2023-01-22T15:16:52.868895Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.868902Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.868908Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.869499Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1854295,
    events_root: None,
}
2023-01-22T15:16:52.869525Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 14
2023-01-22T15:16:52.869549Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::14
2023-01-22T15:16:52.869555Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.869562Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.869568Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.871151Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4270727,
    events_root: None,
}
2023-01-22T15:16:52.871188Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 15
2023-01-22T15:16:52.871211Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::15
2023-01-22T15:16:52.871218Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.871224Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.871230Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.871826Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1866275,
    events_root: None,
}
2023-01-22T15:16:52.871852Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 16
2023-01-22T15:16:52.871876Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::16
2023-01-22T15:16:52.871883Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.871889Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.871895Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.873452Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4273123,
    events_root: None,
}
2023-01-22T15:16:52.873488Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 17
2023-01-22T15:16:52.873511Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::17
2023-01-22T15:16:52.873518Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.873525Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.873531Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.874120Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1868671,
    events_root: None,
}
2023-01-22T15:16:52.874147Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 18
2023-01-22T15:16:52.874170Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::18
2023-01-22T15:16:52.874178Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.874184Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.874190Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.875870Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4258755,
    events_root: None,
}
2023-01-22T15:16:52.875916Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 19
2023-01-22T15:16:52.875948Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::19
2023-01-22T15:16:52.875956Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.875962Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.875968Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.876566Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1854303,
    events_root: None,
}
2023-01-22T15:16:52.876592Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 20
2023-01-22T15:16:52.876615Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::20
2023-01-22T15:16:52.876623Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.876630Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.876635Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.878191Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4236828,
    events_root: None,
}
2023-01-22T15:16:52.878227Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 21
2023-01-22T15:16:52.878250Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::21
2023-01-22T15:16:52.878256Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.878263Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.878270Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.878873Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1831217,
    events_root: None,
}
2023-01-22T15:16:52.878899Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 22
2023-01-22T15:16:52.878922Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::22
2023-01-22T15:16:52.878929Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.878936Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.878942Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.880508Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4262196,
    events_root: None,
}
2023-01-22T15:16:52.880544Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 23
2023-01-22T15:16:52.880567Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::23
2023-01-22T15:16:52.880574Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.880581Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.880587Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.881177Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1856585,
    events_root: None,
}
2023-01-22T15:16:52.881203Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 24
2023-01-22T15:16:52.881226Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::24
2023-01-22T15:16:52.881233Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.881240Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.881246Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.882812Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4274176,
    events_root: None,
}
2023-01-22T15:16:52.882849Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 25
2023-01-22T15:16:52.882872Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::25
2023-01-22T15:16:52.882879Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.882885Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.882891Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.883490Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1868565,
    events_root: None,
}
2023-01-22T15:16:52.883517Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 26
2023-01-22T15:16:52.883539Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::26
2023-01-22T15:16:52.883546Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.883553Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.883559Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.885123Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4276572,
    events_root: None,
}
2023-01-22T15:16:52.885158Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 27
2023-01-22T15:16:52.885182Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::27
2023-01-22T15:16:52.885189Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.885196Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.885202Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.885787Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1870961,
    events_root: None,
}
2023-01-22T15:16:52.885814Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 28
2023-01-22T15:16:52.885838Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::28
2023-01-22T15:16:52.885845Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.885851Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.885857Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.887413Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4262204,
    events_root: None,
}
2023-01-22T15:16:52.887450Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 29
2023-01-22T15:16:52.887478Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::29
2023-01-22T15:16:52.887486Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.887493Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.887498Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.888095Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1856593,
    events_root: None,
}
2023-01-22T15:16:52.888122Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 30
2023-01-22T15:16:52.888144Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::30
2023-01-22T15:16:52.888151Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.888159Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.888165Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.889812Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4739573,
    events_root: None,
}
2023-01-22T15:16:52.889848Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 31
2023-01-22T15:16:52.889872Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::31
2023-01-22T15:16:52.889879Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.889885Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.889891Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.890616Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2818071,
    events_root: None,
}
2023-01-22T15:16:52.890644Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 32
2023-01-22T15:16:52.890667Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::32
2023-01-22T15:16:52.890674Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.890681Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.890687Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.892321Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4780398,
    events_root: None,
}
2023-01-22T15:16:52.892357Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 33
2023-01-22T15:16:52.892385Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::33
2023-01-22T15:16:52.892395Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.892404Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.892412Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.893180Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2843439,
    events_root: None,
}
2023-01-22T15:16:52.893209Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 34
2023-01-22T15:16:52.893235Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::34
2023-01-22T15:16:52.893242Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.893249Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.893255Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.895151Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4792378,
    events_root: None,
}
2023-01-22T15:16:52.895217Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 35
2023-01-22T15:16:52.895260Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::35
2023-01-22T15:16:52.895268Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.895275Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.895281Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.896098Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2855419,
    events_root: None,
}
2023-01-22T15:16:52.896128Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 36
2023-01-22T15:16:52.896153Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::36
2023-01-22T15:16:52.896160Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.896167Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.896173Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.897827Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4794774,
    events_root: None,
}
2023-01-22T15:16:52.897864Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 37
2023-01-22T15:16:52.897888Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::37
2023-01-22T15:16:52.897895Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.897901Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.897907Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.898628Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2857815,
    events_root: None,
}
2023-01-22T15:16:52.898656Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 38
2023-01-22T15:16:52.898679Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::38
2023-01-22T15:16:52.898686Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.898693Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.898699Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.900334Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4780406,
    events_root: None,
}
2023-01-22T15:16:52.900371Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 39
2023-01-22T15:16:52.900394Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::39
2023-01-22T15:16:52.900401Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.900408Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.900414Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.901149Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2843447,
    events_root: None,
}
2023-01-22T15:16:52.901178Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 40
2023-01-22T15:16:52.901201Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::40
2023-01-22T15:16:52.901208Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.901216Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.901222Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.902289Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3888701,
    events_root: None,
}
2023-01-22T15:16:52.902323Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 41
2023-01-22T15:16:52.902346Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::41
2023-01-22T15:16:52.902353Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.902359Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.902365Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.903287Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3369197,
    events_root: None,
}
2023-01-22T15:16:52.903318Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 42
2023-01-22T15:16:52.903341Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::42
2023-01-22T15:16:52.903347Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.903355Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.903361Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.904409Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3830685,
    events_root: None,
}
2023-01-22T15:16:52.904443Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 43
2023-01-22T15:16:52.904473Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::43
2023-01-22T15:16:52.904480Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.904487Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.904493Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.905400Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394565,
    events_root: None,
}
2023-01-22T15:16:52.905430Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 44
2023-01-22T15:16:52.905453Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::44
2023-01-22T15:16:52.905460Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.905467Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.905476Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.906523Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3842665,
    events_root: None,
}
2023-01-22T15:16:52.906556Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 45
2023-01-22T15:16:52.906579Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::45
2023-01-22T15:16:52.906587Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.906596Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.906604Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.907537Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3406545,
    events_root: None,
}
2023-01-22T15:16:52.907569Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 46
2023-01-22T15:16:52.907593Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::46
2023-01-22T15:16:52.907600Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.907607Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.907612Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.908650Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3845061,
    events_root: None,
}
2023-01-22T15:16:52.908684Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 47
2023-01-22T15:16:52.908708Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::47
2023-01-22T15:16:52.908715Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.908722Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.908728Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.909627Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3408941,
    events_root: None,
}
2023-01-22T15:16:52.909658Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 48
2023-01-22T15:16:52.909681Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::48
2023-01-22T15:16:52.909688Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.909695Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.909701Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.910730Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3830693,
    events_root: None,
}
2023-01-22T15:16:52.910763Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 49
2023-01-22T15:16:52.910786Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::49
2023-01-22T15:16:52.910793Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.910801Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.910807Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.911705Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394573,
    events_root: None,
}
2023-01-22T15:16:52.911735Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 50
2023-01-22T15:16:52.911758Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::50
2023-01-22T15:16:52.911765Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.911771Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.911778Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.912560Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3495633,
    events_root: None,
}
2023-01-22T15:16:52.912589Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 51
2023-01-22T15:16:52.912611Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::51
2023-01-22T15:16:52.912618Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.912625Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.912632Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.913532Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3369677,
    events_root: None,
}
2023-01-22T15:16:52.913566Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 52
2023-01-22T15:16:52.913593Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::52
2023-01-22T15:16:52.913600Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.913607Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.913613Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.914481Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3521001,
    events_root: None,
}
2023-01-22T15:16:52.914516Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 53
2023-01-22T15:16:52.914547Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::53
2023-01-22T15:16:52.914554Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.914561Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.914567Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.915600Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3395045,
    events_root: None,
}
2023-01-22T15:16:52.915636Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 54
2023-01-22T15:16:52.915663Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::54
2023-01-22T15:16:52.915670Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.915677Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.915684Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.916498Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3532981,
    events_root: None,
}
2023-01-22T15:16:52.916527Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 55
2023-01-22T15:16:52.916550Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::55
2023-01-22T15:16:52.916557Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.916564Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.916570Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.917474Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3407025,
    events_root: None,
}
2023-01-22T15:16:52.917504Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 56
2023-01-22T15:16:52.917527Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::56
2023-01-22T15:16:52.917534Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.917541Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.917547Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.918331Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3535377,
    events_root: None,
}
2023-01-22T15:16:52.918359Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 57
2023-01-22T15:16:52.918382Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::57
2023-01-22T15:16:52.918389Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.918395Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.918401Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.919314Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3409421,
    events_root: None,
}
2023-01-22T15:16:52.919346Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 58
2023-01-22T15:16:52.919370Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::58
2023-01-22T15:16:52.919377Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.919383Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.919389Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.920197Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3521009,
    events_root: None,
}
2023-01-22T15:16:52.920225Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 59
2023-01-22T15:16:52.920248Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::59
2023-01-22T15:16:52.920255Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.920263Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.920268Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.921155Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3395053,
    events_root: None,
}
2023-01-22T15:16:52.921186Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 60
2023-01-22T15:16:52.921208Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::60
2023-01-22T15:16:52.921215Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.921222Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.921228Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.923262Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5691229,
    events_root: None,
}
2023-01-22T15:16:52.923305Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 61
2023-01-22T15:16:52.923333Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::61
2023-01-22T15:16:52.923340Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.923347Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.923353Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.924281Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3368973,
    events_root: None,
}
2023-01-22T15:16:52.924312Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 62
2023-01-22T15:16:52.924335Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::62
2023-01-22T15:16:52.924342Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.924349Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.924355Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.926214Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5716597,
    events_root: None,
}
2023-01-22T15:16:52.926255Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 63
2023-01-22T15:16:52.926278Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::63
2023-01-22T15:16:52.926285Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.926291Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.926297Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.927190Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394341,
    events_root: None,
}
2023-01-22T15:16:52.927221Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 64
2023-01-22T15:16:52.927244Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::64
2023-01-22T15:16:52.927251Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.927257Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.927263Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.929154Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5728577,
    events_root: None,
}
2023-01-22T15:16:52.929194Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 65
2023-01-22T15:16:52.929218Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::65
2023-01-22T15:16:52.929225Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.929233Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.929239Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.930188Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3406321,
    events_root: None,
}
2023-01-22T15:16:52.930228Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 66
2023-01-22T15:16:52.930258Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::66
2023-01-22T15:16:52.930265Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.930273Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.930279Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.932266Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5730973,
    events_root: None,
}
2023-01-22T15:16:52.932306Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 67
2023-01-22T15:16:52.932331Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::67
2023-01-22T15:16:52.932338Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.932346Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.932352Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.933251Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3408717,
    events_root: None,
}
2023-01-22T15:16:52.933281Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 68
2023-01-22T15:16:52.933304Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::68
2023-01-22T15:16:52.933311Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.933318Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.933324Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-22T15:16:52.935235Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5716605,
    events_root: None,
}
2023-01-22T15:16:52.935277Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 69
2023-01-22T15:16:52.935302Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::69
2023-01-22T15:16:52.935309Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.935316Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.935322Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.936233Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394349,
    events_root: None,
}
2023-01-22T15:16:52.936264Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 70
2023-01-22T15:16:52.936287Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::70
2023-01-22T15:16:52.936293Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.936300Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.936306Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.937299Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3759123,
    events_root: None,
}
2023-01-22T15:16:52.937331Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 71
2023-01-22T15:16:52.937355Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::71
2023-01-22T15:16:52.937362Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.937369Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.937375Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.938260Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3368733,
    events_root: None,
}
2023-01-22T15:16:52.938291Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 72
2023-01-22T15:16:52.938314Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::72
2023-01-22T15:16:52.938320Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.938328Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.938334Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.939325Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3784491,
    events_root: None,
}
2023-01-22T15:16:52.939357Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 73
2023-01-22T15:16:52.939381Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::73
2023-01-22T15:16:52.939388Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.939395Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.939401Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.940324Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394101,
    events_root: None,
}
2023-01-22T15:16:52.940355Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 74
2023-01-22T15:16:52.940378Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::74
2023-01-22T15:16:52.940384Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.940391Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.940397Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.941389Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3796471,
    events_root: None,
}
2023-01-22T15:16:52.941422Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 75
2023-01-22T15:16:52.941445Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::75
2023-01-22T15:16:52.941452Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.941459Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.941465Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.942349Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3406081,
    events_root: None,
}
2023-01-22T15:16:52.942379Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 76
2023-01-22T15:16:52.942402Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::76
2023-01-22T15:16:52.942409Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.942417Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.942423Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.943411Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3798867,
    events_root: None,
}
2023-01-22T15:16:52.943443Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 77
2023-01-22T15:16:52.943473Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::77
2023-01-22T15:16:52.943480Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.943487Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.943493Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.944376Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3408477,
    events_root: None,
}
2023-01-22T15:16:52.944405Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 78
2023-01-22T15:16:52.944429Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::78
2023-01-22T15:16:52.944436Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.944442Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.944448Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.945443Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3784499,
    events_root: None,
}
2023-01-22T15:16:52.945476Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 79
2023-01-22T15:16:52.945500Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::79
2023-01-22T15:16:52.945507Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.945513Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.945519Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-22T15:16:52.946403Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394109,
    events_root: None,
}
2023-01-22T15:16:52.946433Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 80
2023-01-22T15:16:52.946457Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::80
2023-01-22T15:16:52.946464Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.946470Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.946476Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.948469Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5106865,
    events_root: None,
}
2023-01-22T15:16:52.948538Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 81
2023-01-22T15:16:52.948577Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::81
2023-01-22T15:16:52.948585Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.948593Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.948599Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.950380Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4191846,
    events_root: None,
}
2023-01-22T15:16:52.950424Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 82
2023-01-22T15:16:52.950448Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::82
2023-01-22T15:16:52.950455Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.950462Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.950468Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.952215Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4203826,
    events_root: None,
}
2023-01-22T15:16:52.952258Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 83
2023-01-22T15:16:52.952282Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::83
2023-01-22T15:16:52.952288Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.952295Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.952302Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.954036Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4206222,
    events_root: None,
}
2023-01-22T15:16:52.954079Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 84
2023-01-22T15:16:52.954102Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::84
2023-01-22T15:16:52.954109Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.954116Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-22T15:16:52.954122Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-22T15:16:52.955862Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4191854,
    events_root: None,
}
2023-01-22T15:16:52.957718Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-22T15:16:52.957978Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:12.466841533s
```