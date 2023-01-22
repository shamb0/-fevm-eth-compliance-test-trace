> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| KO | under native RT context |

* [FEVM | Eth Compliance Test | Implementation of `delete_actor()` is missing for `test_vm` runtime · Issue #1435 · filecoin-project/ref-fvm](https://github.com/filecoin-project/ref-fvm/issues/1435)

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stBadOpcode/invalidAddr.json#L3520

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
2023-01-19T10:37:04.205580Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json", Total Files :: 1
2023-01-19T10:37:04.206031Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:04.356659Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 222, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.185494Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-19T10:37:16.185681Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-19T10:37:16.185761Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 222, 173, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzacedbbb24k36qqrigv4gkgbtkuv6u2mvq4hztrydhqxxxy5qwumk776
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.188637Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-19T10:37:16.188774Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-19T10:37:16.188816Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 222, 173, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([135, 86, 195, 226, 17, 192, 42, 192, 25, 213, 136, 254, 18, 95, 50, 68, 155, 121, 209, 130]) }
[DEBUG] getting cid: bafy2bzacedxfi7cbcbdgs5tspu7w3e3o7orlghtj6lcjd5gbr2p4ww27ezals
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.191905Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [202]
2023-01-19T10:37:16.192042Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-19T10:37:16.192085Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([121, 46, 44, 168, 100, 157, 195, 57, 208, 185, 119, 244, 82, 48, 8, 55, 203, 168, 19, 62]) }
[DEBUG] getting cid: bafy2bzacebzccxwacolatqwzizmcenr7byvovcqwwqujn2abl6makvwhcqib4
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.194860Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [203]
2023-01-19T10:37:16.194995Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-19T10:37:16.195041Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 204, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([102, 145, 95, 210, 114, 99, 97, 196, 103, 113, 159, 135, 176, 147, 142, 56, 188, 98, 191, 170]) }
[DEBUG] getting cid: bafy2bzacecsq3tuqbkaxqsblsshzvv7oxo2knbz7qnsl22x5z5s3n7zubq35a
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.197872Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [204]
2023-01-19T10:37:16.198236Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-19T10:37:16.199371Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-19T10:37:16.199423Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::0
2023-01-19T10:37:16.199431Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.199439Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.199446Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.200327Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1918592,
    events_root: None,
}
2023-01-19T10:37:16.200357Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-19T10:37:16.200386Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::1
2023-01-19T10:37:16.200393Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.200399Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.200405Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.200977Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1881191,
    events_root: None,
}
2023-01-19T10:37:16.201003Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-19T10:37:16.201031Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::2
2023-01-19T10:37:16.201038Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.201044Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.201050Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.201740Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1943960,
    events_root: None,
}
2023-01-19T10:37:16.201766Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-19T10:37:16.201795Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::3
2023-01-19T10:37:16.201802Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.201808Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.201814Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.202392Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1906559,
    events_root: None,
}
2023-01-19T10:37:16.202418Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 4
2023-01-19T10:37:16.202446Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::4
2023-01-19T10:37:16.202453Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.202460Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.202465Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.203091Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1955940,
    events_root: None,
}
2023-01-19T10:37:16.203117Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 5
2023-01-19T10:37:16.203145Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::5
2023-01-19T10:37:16.203152Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.203159Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.203165Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.203736Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1918539,
    events_root: None,
}
2023-01-19T10:37:16.203761Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 6
2023-01-19T10:37:16.203789Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::6
2023-01-19T10:37:16.203796Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.203803Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.203808Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.204458Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1958336,
    events_root: None,
}
2023-01-19T10:37:16.204484Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 7
2023-01-19T10:37:16.204512Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::7
2023-01-19T10:37:16.204519Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.204527Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.204533Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.205112Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1920935,
    events_root: None,
}
2023-01-19T10:37:16.205137Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 8
2023-01-19T10:37:16.205165Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::8
2023-01-19T10:37:16.205203Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.205210Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.205217Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.205841Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1943968,
    events_root: None,
}
2023-01-19T10:37:16.205867Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 9
2023-01-19T10:37:16.205895Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::9
2023-01-19T10:37:16.205902Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.205909Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.205914Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.206485Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1906567,
    events_root: None,
}
2023-01-19T10:37:16.206510Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 10
2023-01-19T10:37:16.206538Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::10
2023-01-19T10:37:16.206545Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.206552Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.206557Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.208115Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4233379,
    events_root: None,
}
2023-01-19T10:37:16.208149Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 11
2023-01-19T10:37:16.208177Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::11
2023-01-19T10:37:16.208184Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.208192Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.208198Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.208758Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1828927,
    events_root: None,
}
2023-01-19T10:37:16.208783Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 12
2023-01-19T10:37:16.208812Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::12
2023-01-19T10:37:16.208818Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.208825Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.208831Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.210324Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4258747,
    events_root: None,
}
2023-01-19T10:37:16.210359Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 13
2023-01-19T10:37:16.210387Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::13
2023-01-19T10:37:16.210393Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.210400Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.210406Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.210969Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1854295,
    events_root: None,
}
2023-01-19T10:37:16.210994Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 14
2023-01-19T10:37:16.211022Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::14
2023-01-19T10:37:16.211029Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.211035Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.211041Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.212529Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4270727,
    events_root: None,
}
2023-01-19T10:37:16.212563Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 15
2023-01-19T10:37:16.212591Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::15
2023-01-19T10:37:16.212598Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.212606Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.212612Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.213176Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1866275,
    events_root: None,
}
2023-01-19T10:37:16.213201Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 16
2023-01-19T10:37:16.213233Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::16
2023-01-19T10:37:16.213239Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.213248Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.213254Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.214724Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4273123,
    events_root: None,
}
2023-01-19T10:37:16.214758Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 17
2023-01-19T10:37:16.214787Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::17
2023-01-19T10:37:16.214794Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.214800Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.214806Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.215363Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1868671,
    events_root: None,
}
2023-01-19T10:37:16.215388Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 18
2023-01-19T10:37:16.215423Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::18
2023-01-19T10:37:16.215434Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.215445Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.215453Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.216972Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4258755,
    events_root: None,
}
2023-01-19T10:37:16.217006Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 19
2023-01-19T10:37:16.217035Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::19
2023-01-19T10:37:16.217042Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.217048Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.217054Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.217609Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1854303,
    events_root: None,
}
2023-01-19T10:37:16.217634Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 20
2023-01-19T10:37:16.217663Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::20
2023-01-19T10:37:16.217669Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.217676Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.217682Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.219162Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4236828,
    events_root: None,
}
2023-01-19T10:37:16.219196Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 21
2023-01-19T10:37:16.219225Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::21
2023-01-19T10:37:16.219231Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.219238Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.219244Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.219799Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1831217,
    events_root: None,
}
2023-01-19T10:37:16.219828Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 22
2023-01-19T10:37:16.219857Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::22
2023-01-19T10:37:16.219864Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.219870Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.219876Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.221367Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4262196,
    events_root: None,
}
2023-01-19T10:37:16.221402Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 23
2023-01-19T10:37:16.221430Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::23
2023-01-19T10:37:16.221437Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.221444Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.221450Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.222045Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1856585,
    events_root: None,
}
2023-01-19T10:37:16.222070Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 24
2023-01-19T10:37:16.222099Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::24
2023-01-19T10:37:16.222106Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.222112Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.222118Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.223599Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4274176,
    events_root: None,
}
2023-01-19T10:37:16.223633Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 25
2023-01-19T10:37:16.223661Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::25
2023-01-19T10:37:16.223668Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.223674Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.223680Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.224311Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1868565,
    events_root: None,
}
2023-01-19T10:37:16.224336Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 26
2023-01-19T10:37:16.224364Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::26
2023-01-19T10:37:16.224371Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.224378Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.224385Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.225862Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4276572,
    events_root: None,
}
2023-01-19T10:37:16.225896Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 27
2023-01-19T10:37:16.225925Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::27
2023-01-19T10:37:16.225932Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.225938Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.225944Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.226511Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1870961,
    events_root: None,
}
2023-01-19T10:37:16.226536Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 28
2023-01-19T10:37:16.226564Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::28
2023-01-19T10:37:16.226571Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.226578Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.226584Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.228065Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4262204,
    events_root: None,
}
2023-01-19T10:37:16.228100Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 29
2023-01-19T10:37:16.228128Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::29
2023-01-19T10:37:16.228135Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.228141Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.228147Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.228712Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1856593,
    events_root: None,
}
2023-01-19T10:37:16.228737Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 30
2023-01-19T10:37:16.228765Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::30
2023-01-19T10:37:16.228772Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.228779Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.228785Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.230343Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4739573,
    events_root: None,
}
2023-01-19T10:37:16.230377Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 31
2023-01-19T10:37:16.230406Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::31
2023-01-19T10:37:16.230413Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.230419Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.230425Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.231109Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2818071,
    events_root: None,
}
2023-01-19T10:37:16.231135Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 32
2023-01-19T10:37:16.231164Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::32
2023-01-19T10:37:16.231170Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.231177Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.231183Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.232723Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4780398,
    events_root: None,
}
2023-01-19T10:37:16.232757Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 33
2023-01-19T10:37:16.232786Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::33
2023-01-19T10:37:16.232793Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.232799Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.232805Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.233543Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2843439,
    events_root: None,
}
2023-01-19T10:37:16.233569Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 34
2023-01-19T10:37:16.233598Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::34
2023-01-19T10:37:16.233605Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.233611Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.233617Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.235153Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4792378,
    events_root: None,
}
2023-01-19T10:37:16.235188Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 35
2023-01-19T10:37:16.235216Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::35
2023-01-19T10:37:16.235223Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.235230Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.235236Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.235935Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2855419,
    events_root: None,
}
2023-01-19T10:37:16.235961Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 36
2023-01-19T10:37:16.235990Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::36
2023-01-19T10:37:16.235997Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.236003Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.236009Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.237553Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4794774,
    events_root: None,
}
2023-01-19T10:37:16.237588Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 37
2023-01-19T10:37:16.237617Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::37
2023-01-19T10:37:16.237623Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.237630Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.237636Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.238331Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2857815,
    events_root: None,
}
2023-01-19T10:37:16.238357Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 38
2023-01-19T10:37:16.238386Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::38
2023-01-19T10:37:16.238392Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.238399Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.238405Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.239985Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4780406,
    events_root: None,
}
2023-01-19T10:37:16.240020Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 39
2023-01-19T10:37:16.240049Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::39
2023-01-19T10:37:16.240056Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.240063Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.240068Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.240753Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2843447,
    events_root: None,
}
2023-01-19T10:37:16.240780Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 40
2023-01-19T10:37:16.240808Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::40
2023-01-19T10:37:16.240815Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.240822Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.240828Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.241814Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3888701,
    events_root: None,
}
2023-01-19T10:37:16.241846Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 41
2023-01-19T10:37:16.241874Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::41
2023-01-19T10:37:16.241881Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.241888Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.241896Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.242799Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3369197,
    events_root: None,
}
2023-01-19T10:37:16.242828Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 42
2023-01-19T10:37:16.242857Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::42
2023-01-19T10:37:16.242863Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.242870Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.242876Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.243850Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3830685,
    events_root: None,
}
2023-01-19T10:37:16.243882Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 43
2023-01-19T10:37:16.243911Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::43
2023-01-19T10:37:16.243917Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.243924Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.243930Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.244767Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394565,
    events_root: None,
}
2023-01-19T10:37:16.244795Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 44
2023-01-19T10:37:16.244824Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::44
2023-01-19T10:37:16.244831Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.244837Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.244843Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.245807Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3842665,
    events_root: None,
}
2023-01-19T10:37:16.245839Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 45
2023-01-19T10:37:16.245867Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::45
2023-01-19T10:37:16.245874Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.245880Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.245886Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.246722Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3406545,
    events_root: None,
}
2023-01-19T10:37:16.246750Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 46
2023-01-19T10:37:16.246779Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::46
2023-01-19T10:37:16.246785Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.246792Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.246798Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.247796Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3845061,
    events_root: None,
}
2023-01-19T10:37:16.247832Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 47
2023-01-19T10:37:16.247861Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::47
2023-01-19T10:37:16.247868Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.247875Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.247884Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.248794Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3408941,
    events_root: None,
}
2023-01-19T10:37:16.248823Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 48
2023-01-19T10:37:16.248852Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::48
2023-01-19T10:37:16.248859Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.248866Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.248872Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.249855Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3830693,
    events_root: None,
}
2023-01-19T10:37:16.249887Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 49
2023-01-19T10:37:16.249916Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::49
2023-01-19T10:37:16.249923Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.249929Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.249935Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.250779Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394573,
    events_root: None,
}
2023-01-19T10:37:16.250808Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 50
2023-01-19T10:37:16.250836Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::50
2023-01-19T10:37:16.250843Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.250850Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.250855Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.251603Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3495633,
    events_root: None,
}
2023-01-19T10:37:16.251630Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 51
2023-01-19T10:37:16.251659Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::51
2023-01-19T10:37:16.251665Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.251672Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.251678Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.252558Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3369677,
    events_root: None,
}
2023-01-19T10:37:16.252587Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 52
2023-01-19T10:37:16.252616Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::52
2023-01-19T10:37:16.252623Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.252629Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.252635Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.253381Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3521001,
    events_root: None,
}
2023-01-19T10:37:16.253408Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 53
2023-01-19T10:37:16.253436Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::53
2023-01-19T10:37:16.253443Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.253450Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.253456Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.254296Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3395045,
    events_root: None,
}
2023-01-19T10:37:16.254324Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 54
2023-01-19T10:37:16.254362Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::54
2023-01-19T10:37:16.254375Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.254385Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.254394Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.255222Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3532981,
    events_root: None,
}
2023-01-19T10:37:16.255249Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 55
2023-01-19T10:37:16.255278Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::55
2023-01-19T10:37:16.255284Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.255291Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.255297Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.256151Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3407025,
    events_root: None,
}
2023-01-19T10:37:16.256180Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 56
2023-01-19T10:37:16.256209Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::56
2023-01-19T10:37:16.256216Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.256222Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.256228Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.256998Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3535377,
    events_root: None,
}
2023-01-19T10:37:16.257026Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 57
2023-01-19T10:37:16.257055Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::57
2023-01-19T10:37:16.257062Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.257068Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.257074Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.258025Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3409421,
    events_root: None,
}
2023-01-19T10:37:16.258055Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 58
2023-01-19T10:37:16.258084Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::58
2023-01-19T10:37:16.258091Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.258097Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.258103Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.258862Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3521009,
    events_root: None,
}
2023-01-19T10:37:16.258890Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 59
2023-01-19T10:37:16.258919Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::59
2023-01-19T10:37:16.258925Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.258932Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.258938Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.259802Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3395053,
    events_root: None,
}
2023-01-19T10:37:16.259842Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 60
2023-01-19T10:37:16.259873Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::60
2023-01-19T10:37:16.259880Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.259887Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.259893Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.261752Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5691229,
    events_root: None,
}
2023-01-19T10:37:16.261791Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 61
2023-01-19T10:37:16.261821Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::61
2023-01-19T10:37:16.261827Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.261834Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.261840Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.262694Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3368973,
    events_root: None,
}
2023-01-19T10:37:16.262722Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 62
2023-01-19T10:37:16.262751Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::62
2023-01-19T10:37:16.262758Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.262765Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.262771Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.264567Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5716597,
    events_root: None,
}
2023-01-19T10:37:16.264606Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 63
2023-01-19T10:37:16.264636Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::63
2023-01-19T10:37:16.264642Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.264649Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.264655Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.265524Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394341,
    events_root: None,
}
2023-01-19T10:37:16.265553Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 64
2023-01-19T10:37:16.265583Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::64
2023-01-19T10:37:16.265590Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.265597Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.265603Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.267613Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5728577,
    events_root: None,
}
2023-01-19T10:37:16.267655Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 65
2023-01-19T10:37:16.267687Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::65
2023-01-19T10:37:16.267694Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.267700Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.267706Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.268600Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3406321,
    events_root: None,
}
2023-01-19T10:37:16.268629Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 66
2023-01-19T10:37:16.268658Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::66
2023-01-19T10:37:16.268665Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.268672Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.268678Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.270477Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5730973,
    events_root: None,
}
2023-01-19T10:37:16.270518Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 67
2023-01-19T10:37:16.270550Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::67
2023-01-19T10:37:16.270557Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.270564Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.270571Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.271586Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3408717,
    events_root: None,
}
2023-01-19T10:37:16.271615Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 68
2023-01-19T10:37:16.271659Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::68
2023-01-19T10:37:16.271666Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.271672Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.271678Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.273524Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5716605,
    events_root: None,
}
2023-01-19T10:37:16.273562Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 69
2023-01-19T10:37:16.273591Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::69
2023-01-19T10:37:16.273598Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.273605Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.273610Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.274476Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394349,
    events_root: None,
}
2023-01-19T10:37:16.274506Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 70
2023-01-19T10:37:16.274535Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::70
2023-01-19T10:37:16.274541Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.274548Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.274554Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.275554Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3759123,
    events_root: None,
}
2023-01-19T10:37:16.275585Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 71
2023-01-19T10:37:16.275615Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::71
2023-01-19T10:37:16.275622Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.275629Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.275635Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.276509Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3368733,
    events_root: None,
}
2023-01-19T10:37:16.276538Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 72
2023-01-19T10:37:16.276567Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::72
2023-01-19T10:37:16.276574Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.276581Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.276586Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.277548Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3784491,
    events_root: None,
}
2023-01-19T10:37:16.277579Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 73
2023-01-19T10:37:16.277609Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::73
2023-01-19T10:37:16.277615Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.277622Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.277628Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.278650Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394101,
    events_root: None,
}
2023-01-19T10:37:16.278679Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 74
2023-01-19T10:37:16.278708Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::74
2023-01-19T10:37:16.278715Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.278721Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.278727Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.279692Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3796471,
    events_root: None,
}
2023-01-19T10:37:16.279724Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 75
2023-01-19T10:37:16.279753Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::75
2023-01-19T10:37:16.279759Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.279766Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.279772Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.280639Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3406081,
    events_root: None,
}
2023-01-19T10:37:16.280668Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 76
2023-01-19T10:37:16.280697Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::76
2023-01-19T10:37:16.280704Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.280711Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.280716Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.281679Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3798867,
    events_root: None,
}
2023-01-19T10:37:16.281710Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 77
2023-01-19T10:37:16.281739Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::77
2023-01-19T10:37:16.281746Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.281752Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.281758Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.282622Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3408477,
    events_root: None,
}
2023-01-19T10:37:16.282651Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 78
2023-01-19T10:37:16.282681Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::78
2023-01-19T10:37:16.282688Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.282694Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.282700Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.283667Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3784499,
    events_root: None,
}
2023-01-19T10:37:16.283699Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 79
2023-01-19T10:37:16.283728Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::79
2023-01-19T10:37:16.283734Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.283741Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.283746Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.284622Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394109,
    events_root: None,
}
2023-01-19T10:37:16.284656Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 80
2023-01-19T10:37:16.284697Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::80
2023-01-19T10:37:16.284708Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.284718Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.284727Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.287376Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6760163,
    events_root: None,
}
2023-01-19T10:37:16.287420Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 81
2023-01-19T10:37:16.287448Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::81
2023-01-19T10:37:16.287455Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.287462Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.287467Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.289331Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5132233,
    events_root: None,
}
2023-01-19T10:37:16.289376Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 82
2023-01-19T10:37:16.289406Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::82
2023-01-19T10:37:16.289412Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.289419Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.289425Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.291100Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4203826,
    events_root: None,
}
2023-01-19T10:37:16.291139Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 83
2023-01-19T10:37:16.291169Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::83
2023-01-19T10:37:16.291176Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.291182Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.291188Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.292891Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4206222,
    events_root: None,
}
2023-01-19T10:37:16.292929Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 84
2023-01-19T10:37:16.292958Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Istanbul::84
2023-01-19T10:37:16.292965Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.292972Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.292978Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.294657Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4191854,
    events_root: None,
}
2023-01-19T10:37:16.294698Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-19T10:37:16.294727Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::0
2023-01-19T10:37:16.294734Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.294741Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.294747Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.295518Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2864889,
    events_root: None,
}
2023-01-19T10:37:16.295547Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-19T10:37:16.295576Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::1
2023-01-19T10:37:16.295582Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.295589Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.295595Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.296307Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2801386,
    events_root: None,
}
2023-01-19T10:37:16.296334Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-19T10:37:16.296363Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::2
2023-01-19T10:37:16.296370Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.296377Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.296383Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.297191Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2874617,
    events_root: None,
}
2023-01-19T10:37:16.297220Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-19T10:37:16.297249Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::3
2023-01-19T10:37:16.297256Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.297262Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.297268Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.297972Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2826754,
    events_root: None,
}
2023-01-19T10:37:16.297999Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 4
2023-01-19T10:37:16.298028Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::4
2023-01-19T10:37:16.298034Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.298041Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.298047Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.298810Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2886597,
    events_root: None,
}
2023-01-19T10:37:16.298838Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 5
2023-01-19T10:37:16.298867Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::5
2023-01-19T10:37:16.298874Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.298880Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.298886Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.299593Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2838734,
    events_root: None,
}
2023-01-19T10:37:16.299621Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 6
2023-01-19T10:37:16.299650Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::6
2023-01-19T10:37:16.299656Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.299663Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.299669Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.300436Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2888993,
    events_root: None,
}
2023-01-19T10:37:16.300465Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 7
2023-01-19T10:37:16.300494Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::7
2023-01-19T10:37:16.300501Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.300507Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.300513Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.301215Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2841130,
    events_root: None,
}
2023-01-19T10:37:16.301242Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 8
2023-01-19T10:37:16.301272Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::8
2023-01-19T10:37:16.301279Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.301285Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.301291Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.302047Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2874625,
    events_root: None,
}
2023-01-19T10:37:16.302076Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 9
2023-01-19T10:37:16.302105Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::9
2023-01-19T10:37:16.302111Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.302118Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.302124Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.302827Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2826762,
    events_root: None,
}
2023-01-19T10:37:16.302854Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 10
2023-01-19T10:37:16.302883Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::10
2023-01-19T10:37:16.302890Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.302896Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.302902Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.304469Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4233379,
    events_root: None,
}
2023-01-19T10:37:16.304504Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 11
2023-01-19T10:37:16.304533Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::11
2023-01-19T10:37:16.304540Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.304546Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.304552Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.305123Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1828927,
    events_root: None,
}
2023-01-19T10:37:16.305148Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 12
2023-01-19T10:37:16.305177Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::12
2023-01-19T10:37:16.305184Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.305190Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.305196Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.306729Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4258747,
    events_root: None,
}
2023-01-19T10:37:16.306764Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 13
2023-01-19T10:37:16.306792Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::13
2023-01-19T10:37:16.306799Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.306806Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.306811Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.307380Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1854295,
    events_root: None,
}
2023-01-19T10:37:16.307406Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 14
2023-01-19T10:37:16.307435Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::14
2023-01-19T10:37:16.307443Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.307450Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.307457Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.308991Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4270727,
    events_root: None,
}
2023-01-19T10:37:16.309026Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 15
2023-01-19T10:37:16.309055Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::15
2023-01-19T10:37:16.309062Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.309069Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.309075Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.309648Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1866275,
    events_root: None,
}
2023-01-19T10:37:16.309673Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 16
2023-01-19T10:37:16.309702Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::16
2023-01-19T10:37:16.309709Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.309715Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.309721Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.311227Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4273123,
    events_root: None,
}
2023-01-19T10:37:16.311262Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 17
2023-01-19T10:37:16.311291Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::17
2023-01-19T10:37:16.311298Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.311304Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.311310Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.311898Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1868671,
    events_root: None,
}
2023-01-19T10:37:16.311923Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 18
2023-01-19T10:37:16.311952Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::18
2023-01-19T10:37:16.311959Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.311966Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.311972Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.313529Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4258755,
    events_root: None,
}
2023-01-19T10:37:16.313564Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 19
2023-01-19T10:37:16.313593Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::19
2023-01-19T10:37:16.313600Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.313607Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.313613Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.314184Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1854303,
    events_root: None,
}
2023-01-19T10:37:16.314209Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 20
2023-01-19T10:37:16.314238Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::20
2023-01-19T10:37:16.314245Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.314251Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.314257Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.315774Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4236828,
    events_root: None,
}
2023-01-19T10:37:16.315809Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 21
2023-01-19T10:37:16.315845Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::21
2023-01-19T10:37:16.315852Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.315859Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.315865Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.316437Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1831217,
    events_root: None,
}
2023-01-19T10:37:16.316463Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 22
2023-01-19T10:37:16.316492Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::22
2023-01-19T10:37:16.316498Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.316505Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.316511Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.318028Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4262196,
    events_root: None,
}
2023-01-19T10:37:16.318063Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 23
2023-01-19T10:37:16.318093Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::23
2023-01-19T10:37:16.318099Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.318106Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.318112Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.318689Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1856585,
    events_root: None,
}
2023-01-19T10:37:16.318714Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 24
2023-01-19T10:37:16.318743Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::24
2023-01-19T10:37:16.318750Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.318757Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.318763Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.320285Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4274176,
    events_root: None,
}
2023-01-19T10:37:16.320320Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 25
2023-01-19T10:37:16.320349Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::25
2023-01-19T10:37:16.320356Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.320362Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.320368Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.320941Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1868565,
    events_root: None,
}
2023-01-19T10:37:16.320966Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 26
2023-01-19T10:37:16.321003Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::26
2023-01-19T10:37:16.321014Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.321024Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.321033Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.322621Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4276572,
    events_root: None,
}
2023-01-19T10:37:16.322657Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 27
2023-01-19T10:37:16.322686Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::27
2023-01-19T10:37:16.322692Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.322699Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.322705Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.323276Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1870961,
    events_root: None,
}
2023-01-19T10:37:16.323302Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 28
2023-01-19T10:37:16.323331Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::28
2023-01-19T10:37:16.323338Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.323344Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.323350Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.324871Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4262204,
    events_root: None,
}
2023-01-19T10:37:16.324907Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 29
2023-01-19T10:37:16.324936Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::29
2023-01-19T10:37:16.324942Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.324949Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.324955Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.325526Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1856593,
    events_root: None,
}
2023-01-19T10:37:16.325551Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 30
2023-01-19T10:37:16.325580Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::30
2023-01-19T10:37:16.325587Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.325594Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.325600Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.327184Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4739573,
    events_root: None,
}
2023-01-19T10:37:16.327220Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 31
2023-01-19T10:37:16.327249Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::31
2023-01-19T10:37:16.327256Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.327262Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.327268Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.327985Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2818071,
    events_root: None,
}
2023-01-19T10:37:16.328013Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 32
2023-01-19T10:37:16.328042Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::32
2023-01-19T10:37:16.328049Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.328055Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.328061Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.329652Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4780398,
    events_root: None,
}
2023-01-19T10:37:16.329687Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 33
2023-01-19T10:37:16.329716Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::33
2023-01-19T10:37:16.329723Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.329729Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.329735Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.330496Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2843439,
    events_root: None,
}
2023-01-19T10:37:16.330524Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 34
2023-01-19T10:37:16.330553Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::34
2023-01-19T10:37:16.330559Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.330566Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.330572Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.332173Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4792378,
    events_root: None,
}
2023-01-19T10:37:16.332209Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 35
2023-01-19T10:37:16.332238Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::35
2023-01-19T10:37:16.332245Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.332252Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.332258Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.332962Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2855419,
    events_root: None,
}
2023-01-19T10:37:16.332989Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 36
2023-01-19T10:37:16.333018Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::36
2023-01-19T10:37:16.333025Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.333031Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.333037Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.334621Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4794774,
    events_root: None,
}
2023-01-19T10:37:16.334656Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 37
2023-01-19T10:37:16.334685Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::37
2023-01-19T10:37:16.334692Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.334699Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.334704Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.335408Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2857815,
    events_root: None,
}
2023-01-19T10:37:16.335434Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 38
2023-01-19T10:37:16.335466Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::38
2023-01-19T10:37:16.335473Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.335479Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.335485Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.337040Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4780406,
    events_root: None,
}
2023-01-19T10:37:16.337074Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 39
2023-01-19T10:37:16.337103Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::39
2023-01-19T10:37:16.337109Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.337116Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.337122Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.337802Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2843447,
    events_root: None,
}
2023-01-19T10:37:16.337829Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 40
2023-01-19T10:37:16.337857Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::40
2023-01-19T10:37:16.337863Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.337870Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.337876Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.338887Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3888701,
    events_root: None,
}
2023-01-19T10:37:16.338919Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 41
2023-01-19T10:37:16.338947Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::41
2023-01-19T10:37:16.338953Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.338960Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.338966Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.339893Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3369197,
    events_root: None,
}
2023-01-19T10:37:16.339923Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 42
2023-01-19T10:37:16.339952Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::42
2023-01-19T10:37:16.339959Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.339965Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.339971Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.340960Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3830685,
    events_root: None,
}
2023-01-19T10:37:16.340993Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 43
2023-01-19T10:37:16.341022Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::43
2023-01-19T10:37:16.341029Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.341035Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.341041Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.341895Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394565,
    events_root: None,
}
2023-01-19T10:37:16.341925Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 44
2023-01-19T10:37:16.341953Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::44
2023-01-19T10:37:16.341960Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.341967Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.341972Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.343067Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3842665,
    events_root: None,
}
2023-01-19T10:37:16.343101Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 45
2023-01-19T10:37:16.343132Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::45
2023-01-19T10:37:16.343139Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.343145Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.343151Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.344041Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3406545,
    events_root: None,
}
2023-01-19T10:37:16.344070Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 46
2023-01-19T10:37:16.344099Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::46
2023-01-19T10:37:16.344106Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.344112Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.344118Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.345103Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3845061,
    events_root: None,
}
2023-01-19T10:37:16.345135Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 47
2023-01-19T10:37:16.345164Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::47
2023-01-19T10:37:16.345171Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.345178Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.345183Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.346033Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3408941,
    events_root: None,
}
2023-01-19T10:37:16.346067Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 48
2023-01-19T10:37:16.346109Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::48
2023-01-19T10:37:16.346119Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.346129Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.346138Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.347144Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3830693,
    events_root: None,
}
2023-01-19T10:37:16.347176Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 49
2023-01-19T10:37:16.347205Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::49
2023-01-19T10:37:16.347212Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.347218Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.347224Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.348086Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394573,
    events_root: None,
}
2023-01-19T10:37:16.348115Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 50
2023-01-19T10:37:16.348144Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::50
2023-01-19T10:37:16.348150Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.348157Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.348163Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.348915Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3495633,
    events_root: None,
}
2023-01-19T10:37:16.348943Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 51
2023-01-19T10:37:16.348971Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::51
2023-01-19T10:37:16.348978Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.348985Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.348990Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.349842Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3369677,
    events_root: None,
}
2023-01-19T10:37:16.349870Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 52
2023-01-19T10:37:16.349899Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::52
2023-01-19T10:37:16.349906Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.349913Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.349918Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.350680Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3521001,
    events_root: None,
}
2023-01-19T10:37:16.350707Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 53
2023-01-19T10:37:16.350736Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::53
2023-01-19T10:37:16.350743Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.350749Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.350755Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.351614Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3395045,
    events_root: None,
}
2023-01-19T10:37:16.351643Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 54
2023-01-19T10:37:16.351672Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::54
2023-01-19T10:37:16.351679Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.351685Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.351691Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.352507Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3532981,
    events_root: None,
}
2023-01-19T10:37:16.352535Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 55
2023-01-19T10:37:16.352564Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::55
2023-01-19T10:37:16.352571Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.352578Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.352584Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.353429Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3407025,
    events_root: None,
}
2023-01-19T10:37:16.353457Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 56
2023-01-19T10:37:16.353486Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::56
2023-01-19T10:37:16.353492Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.353499Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.353505Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.354251Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3535377,
    events_root: None,
}
2023-01-19T10:37:16.354278Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 57
2023-01-19T10:37:16.354306Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::57
2023-01-19T10:37:16.354313Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.354320Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.354325Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.355170Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3409421,
    events_root: None,
}
2023-01-19T10:37:16.355198Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 58
2023-01-19T10:37:16.355257Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::58
2023-01-19T10:37:16.355264Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.355271Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.355277Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.356032Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3521009,
    events_root: None,
}
2023-01-19T10:37:16.356060Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 59
2023-01-19T10:37:16.356088Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::59
2023-01-19T10:37:16.356095Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.356102Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.356108Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.356945Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3395053,
    events_root: None,
}
2023-01-19T10:37:16.356973Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 60
2023-01-19T10:37:16.357002Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::60
2023-01-19T10:37:16.357008Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.357015Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.357021Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.358778Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5691229,
    events_root: None,
}
2023-01-19T10:37:16.358816Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 61
2023-01-19T10:37:16.358844Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::61
2023-01-19T10:37:16.358851Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.358859Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.358868Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.359758Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3368973,
    events_root: None,
}
2023-01-19T10:37:16.359787Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 62
2023-01-19T10:37:16.359815Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::62
2023-01-19T10:37:16.359822Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.359848Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.359853Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.361607Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5716597,
    events_root: None,
}
2023-01-19T10:37:16.361645Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 63
2023-01-19T10:37:16.361674Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::63
2023-01-19T10:37:16.361681Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.361687Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.361693Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.362533Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394341,
    events_root: None,
}
2023-01-19T10:37:16.362562Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 64
2023-01-19T10:37:16.362591Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::64
2023-01-19T10:37:16.362597Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.362604Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.362610Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.364380Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5728577,
    events_root: None,
}
2023-01-19T10:37:16.364417Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 65
2023-01-19T10:37:16.364446Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::65
2023-01-19T10:37:16.364452Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.364459Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.364465Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.365308Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3406321,
    events_root: None,
}
2023-01-19T10:37:16.365337Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 66
2023-01-19T10:37:16.365366Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::66
2023-01-19T10:37:16.365372Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.365379Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.365385Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.367134Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5730973,
    events_root: None,
}
2023-01-19T10:37:16.367172Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 67
2023-01-19T10:37:16.367200Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::67
2023-01-19T10:37:16.367207Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.367213Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.367219Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.368122Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3408717,
    events_root: None,
}
2023-01-19T10:37:16.368151Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 68
2023-01-19T10:37:16.368180Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::68
2023-01-19T10:37:16.368186Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.368193Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.368199Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.369964Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5716605,
    events_root: None,
}
2023-01-19T10:37:16.370003Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 69
2023-01-19T10:37:16.370031Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::69
2023-01-19T10:37:16.370038Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.370045Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.370050Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.370896Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394349,
    events_root: None,
}
2023-01-19T10:37:16.370925Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 70
2023-01-19T10:37:16.370953Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::70
2023-01-19T10:37:16.370960Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.370967Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.370972Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.371954Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3759123,
    events_root: None,
}
2023-01-19T10:37:16.371986Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 71
2023-01-19T10:37:16.372015Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::71
2023-01-19T10:37:16.372021Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.372028Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.372034Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.372870Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3368733,
    events_root: None,
}
2023-01-19T10:37:16.372898Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 72
2023-01-19T10:37:16.372927Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::72
2023-01-19T10:37:16.372934Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.372941Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.372946Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.373889Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3784491,
    events_root: None,
}
2023-01-19T10:37:16.373921Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 73
2023-01-19T10:37:16.373949Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::73
2023-01-19T10:37:16.373956Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.373963Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.373968Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.374812Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394101,
    events_root: None,
}
2023-01-19T10:37:16.374846Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 74
2023-01-19T10:37:16.374888Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::74
2023-01-19T10:37:16.374898Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.374909Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.374918Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.375892Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3796471,
    events_root: None,
}
2023-01-19T10:37:16.375924Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 75
2023-01-19T10:37:16.375953Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::75
2023-01-19T10:37:16.375959Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.375966Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.375972Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.376817Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3406081,
    events_root: None,
}
2023-01-19T10:37:16.376846Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 76
2023-01-19T10:37:16.376874Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::76
2023-01-19T10:37:16.376881Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.376888Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.376893Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.377839Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3798867,
    events_root: None,
}
2023-01-19T10:37:16.377870Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 77
2023-01-19T10:37:16.377899Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::77
2023-01-19T10:37:16.377906Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.377912Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.377918Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.378769Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3408477,
    events_root: None,
}
2023-01-19T10:37:16.378798Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 78
2023-01-19T10:37:16.378827Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::78
2023-01-19T10:37:16.378833Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.378840Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.378846Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.379789Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3784499,
    events_root: None,
}
2023-01-19T10:37:16.379819Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 79
2023-01-19T10:37:16.379856Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::79
2023-01-19T10:37:16.379863Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.379870Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.379876Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.380715Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394109,
    events_root: None,
}
2023-01-19T10:37:16.380744Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 80
2023-01-19T10:37:16.380773Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::80
2023-01-19T10:37:16.380780Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.380786Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.380792Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.382614Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5106865,
    events_root: None,
}
2023-01-19T10:37:16.382654Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 81
2023-01-19T10:37:16.382682Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::81
2023-01-19T10:37:16.382689Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.382696Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.382702Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.384361Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4191846,
    events_root: None,
}
2023-01-19T10:37:16.384399Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 82
2023-01-19T10:37:16.384428Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::82
2023-01-19T10:37:16.384435Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.384441Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.384447Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.386091Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4203826,
    events_root: None,
}
2023-01-19T10:37:16.386129Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 83
2023-01-19T10:37:16.386157Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::83
2023-01-19T10:37:16.386164Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.386171Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.386176Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.387823Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4206222,
    events_root: None,
}
2023-01-19T10:37:16.387869Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 84
2023-01-19T10:37:16.387898Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Berlin::84
2023-01-19T10:37:16.387905Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.387912Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.387917Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.389592Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4191854,
    events_root: None,
}
2023-01-19T10:37:16.389634Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-19T10:37:16.389663Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::0
2023-01-19T10:37:16.389669Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.389676Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.389682Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.390424Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2864889,
    events_root: None,
}
2023-01-19T10:37:16.390452Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-19T10:37:16.390481Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::1
2023-01-19T10:37:16.390488Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.390494Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.390500Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.391191Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2801386,
    events_root: None,
}
2023-01-19T10:37:16.391218Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-19T10:37:16.391247Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::2
2023-01-19T10:37:16.391253Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.391260Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.391266Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.392021Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2874617,
    events_root: None,
}
2023-01-19T10:37:16.392048Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-19T10:37:16.392085Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::3
2023-01-19T10:37:16.392095Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.392106Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.392115Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.392852Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2826754,
    events_root: None,
}
2023-01-19T10:37:16.392878Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 4
2023-01-19T10:37:16.392907Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::4
2023-01-19T10:37:16.392914Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.392920Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.392926Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.393675Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2886597,
    events_root: None,
}
2023-01-19T10:37:16.393703Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 5
2023-01-19T10:37:16.393732Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::5
2023-01-19T10:37:16.393738Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.393745Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.393751Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.394443Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2838734,
    events_root: None,
}
2023-01-19T10:37:16.394470Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 6
2023-01-19T10:37:16.394499Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::6
2023-01-19T10:37:16.394506Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.394512Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.394518Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.395262Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2888993,
    events_root: None,
}
2023-01-19T10:37:16.395290Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 7
2023-01-19T10:37:16.395319Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::7
2023-01-19T10:37:16.395326Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.395332Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.395338Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.396035Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2841130,
    events_root: None,
}
2023-01-19T10:37:16.396061Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 8
2023-01-19T10:37:16.396090Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::8
2023-01-19T10:37:16.396097Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.396104Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.396109Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.396859Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2874625,
    events_root: None,
}
2023-01-19T10:37:16.396887Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 9
2023-01-19T10:37:16.396915Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::9
2023-01-19T10:37:16.396922Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.396929Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.396935Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.397624Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2826762,
    events_root: None,
}
2023-01-19T10:37:16.397650Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 10
2023-01-19T10:37:16.397679Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::10
2023-01-19T10:37:16.397686Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.397693Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.397699Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.399183Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4233379,
    events_root: None,
}
2023-01-19T10:37:16.399217Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 11
2023-01-19T10:37:16.399252Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::11
2023-01-19T10:37:16.399263Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.399274Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.399283Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.399896Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1828927,
    events_root: None,
}
2023-01-19T10:37:16.399921Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 12
2023-01-19T10:37:16.399950Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::12
2023-01-19T10:37:16.399956Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.399963Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.399969Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.401451Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4258747,
    events_root: None,
}
2023-01-19T10:37:16.401485Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 13
2023-01-19T10:37:16.401513Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::13
2023-01-19T10:37:16.401520Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.401527Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.401533Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.402093Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1854295,
    events_root: None,
}
2023-01-19T10:37:16.402118Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 14
2023-01-19T10:37:16.402146Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::14
2023-01-19T10:37:16.402153Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.402159Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.402165Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.403645Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4270727,
    events_root: None,
}
2023-01-19T10:37:16.403680Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 15
2023-01-19T10:37:16.403708Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::15
2023-01-19T10:37:16.403715Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.403722Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.403727Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.404292Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1866275,
    events_root: None,
}
2023-01-19T10:37:16.404317Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 16
2023-01-19T10:37:16.404346Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::16
2023-01-19T10:37:16.404352Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.404359Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.404365Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.405882Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4273123,
    events_root: None,
}
2023-01-19T10:37:16.405917Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 17
2023-01-19T10:37:16.405945Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::17
2023-01-19T10:37:16.405952Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.405959Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.405965Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.406524Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1868671,
    events_root: None,
}
2023-01-19T10:37:16.406549Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 18
2023-01-19T10:37:16.406580Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::18
2023-01-19T10:37:16.406588Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.406596Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.406601Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.408087Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4258755,
    events_root: None,
}
2023-01-19T10:37:16.408131Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 19
2023-01-19T10:37:16.408173Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::19
2023-01-19T10:37:16.408183Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.408194Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.408203Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.408793Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1854303,
    events_root: None,
}
2023-01-19T10:37:16.408818Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 20
2023-01-19T10:37:16.408847Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::20
2023-01-19T10:37:16.408853Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.408860Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.408866Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.410341Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4236828,
    events_root: None,
}
2023-01-19T10:37:16.410375Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 21
2023-01-19T10:37:16.410404Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::21
2023-01-19T10:37:16.410411Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.410417Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.410423Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.410979Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1831217,
    events_root: None,
}
2023-01-19T10:37:16.411005Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 22
2023-01-19T10:37:16.411033Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::22
2023-01-19T10:37:16.411040Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.411046Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.411052Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.412545Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4262196,
    events_root: None,
}
2023-01-19T10:37:16.412580Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 23
2023-01-19T10:37:16.412613Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::23
2023-01-19T10:37:16.412620Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.412627Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.412633Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.413193Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1856585,
    events_root: None,
}
2023-01-19T10:37:16.413218Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 24
2023-01-19T10:37:16.413247Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::24
2023-01-19T10:37:16.413253Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.413260Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.413266Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.414750Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4274176,
    events_root: None,
}
2023-01-19T10:37:16.414785Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 25
2023-01-19T10:37:16.414813Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::25
2023-01-19T10:37:16.414820Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.414827Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.414833Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.415392Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1868565,
    events_root: None,
}
2023-01-19T10:37:16.415418Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 26
2023-01-19T10:37:16.415446Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::26
2023-01-19T10:37:16.415453Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.415459Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.415465Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.417016Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4276572,
    events_root: None,
}
2023-01-19T10:37:16.417051Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 27
2023-01-19T10:37:16.417079Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::27
2023-01-19T10:37:16.417086Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.417093Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.417099Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.417659Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1870961,
    events_root: None,
}
2023-01-19T10:37:16.417684Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 28
2023-01-19T10:37:16.417713Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::28
2023-01-19T10:37:16.417720Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.417726Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.417732Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.419210Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4262204,
    events_root: None,
}
2023-01-19T10:37:16.419245Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 29
2023-01-19T10:37:16.419274Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::29
2023-01-19T10:37:16.419280Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.419287Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.419293Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.419858Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1856593,
    events_root: None,
}
2023-01-19T10:37:16.419884Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 30
2023-01-19T10:37:16.419912Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::30
2023-01-19T10:37:16.419919Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.419926Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.419931Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.421471Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4739573,
    events_root: None,
}
2023-01-19T10:37:16.421506Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 31
2023-01-19T10:37:16.421535Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::31
2023-01-19T10:37:16.421542Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.421548Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.421554Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.422271Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2818071,
    events_root: None,
}
2023-01-19T10:37:16.422297Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 32
2023-01-19T10:37:16.422326Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::32
2023-01-19T10:37:16.422333Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.422339Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.422345Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.423900Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4780398,
    events_root: None,
}
2023-01-19T10:37:16.423935Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 33
2023-01-19T10:37:16.423964Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::33
2023-01-19T10:37:16.423970Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.423977Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.423983Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.424669Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2843439,
    events_root: None,
}
2023-01-19T10:37:16.424696Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 34
2023-01-19T10:37:16.424724Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::34
2023-01-19T10:37:16.424731Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.424738Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.424746Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.426343Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4792378,
    events_root: None,
}
2023-01-19T10:37:16.426378Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 35
2023-01-19T10:37:16.426406Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::35
2023-01-19T10:37:16.426413Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.426420Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.426425Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.427112Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2855419,
    events_root: None,
}
2023-01-19T10:37:16.427139Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 36
2023-01-19T10:37:16.427167Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::36
2023-01-19T10:37:16.427174Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.427180Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.427186Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.428741Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4794774,
    events_root: None,
}
2023-01-19T10:37:16.428776Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 37
2023-01-19T10:37:16.428805Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::37
2023-01-19T10:37:16.428812Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.428818Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.428824Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.429511Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2857815,
    events_root: None,
}
2023-01-19T10:37:16.429538Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 38
2023-01-19T10:37:16.429566Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::38
2023-01-19T10:37:16.429573Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.429580Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.429585Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.431126Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4780406,
    events_root: None,
}
2023-01-19T10:37:16.431160Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 39
2023-01-19T10:37:16.431189Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::39
2023-01-19T10:37:16.431196Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.431202Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.431208Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.431900Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2843447,
    events_root: None,
}
2023-01-19T10:37:16.431927Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 40
2023-01-19T10:37:16.431956Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::40
2023-01-19T10:37:16.431963Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.431969Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.431975Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.432949Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3888701,
    events_root: None,
}
2023-01-19T10:37:16.432980Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 41
2023-01-19T10:37:16.433009Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::41
2023-01-19T10:37:16.433016Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.433022Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.433028Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.433932Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3369197,
    events_root: None,
}
2023-01-19T10:37:16.433961Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 42
2023-01-19T10:37:16.433990Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::42
2023-01-19T10:37:16.433997Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.434003Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.434009Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.434990Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3830685,
    events_root: None,
}
2023-01-19T10:37:16.435021Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 43
2023-01-19T10:37:16.435050Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::43
2023-01-19T10:37:16.435057Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.435063Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.435069Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.435917Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394565,
    events_root: None,
}
2023-01-19T10:37:16.435946Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 44
2023-01-19T10:37:16.435975Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::44
2023-01-19T10:37:16.435982Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.435989Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.435995Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.436970Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3842665,
    events_root: None,
}
2023-01-19T10:37:16.437002Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 45
2023-01-19T10:37:16.437031Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::45
2023-01-19T10:37:16.437038Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.437044Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.437050Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.437899Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3406545,
    events_root: None,
}
2023-01-19T10:37:16.437928Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 46
2023-01-19T10:37:16.437957Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::46
2023-01-19T10:37:16.437964Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.437970Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.437976Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.438987Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3845061,
    events_root: None,
}
2023-01-19T10:37:16.439019Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 47
2023-01-19T10:37:16.439047Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::47
2023-01-19T10:37:16.439054Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.439061Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.439066Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.439915Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3408941,
    events_root: None,
}
2023-01-19T10:37:16.439944Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 48
2023-01-19T10:37:16.439972Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::48
2023-01-19T10:37:16.439979Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.439986Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.439992Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.441021Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3830693,
    events_root: None,
}
2023-01-19T10:37:16.441052Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 49
2023-01-19T10:37:16.441081Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::49
2023-01-19T10:37:16.441088Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.441094Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.441100Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.441942Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394573,
    events_root: None,
}
2023-01-19T10:37:16.441971Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 50
2023-01-19T10:37:16.442000Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::50
2023-01-19T10:37:16.442006Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.442013Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.442019Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.442765Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3495633,
    events_root: None,
}
2023-01-19T10:37:16.442792Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 51
2023-01-19T10:37:16.442821Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::51
2023-01-19T10:37:16.442828Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.442834Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.442840Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.443681Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3369677,
    events_root: None,
}
2023-01-19T10:37:16.443710Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 52
2023-01-19T10:37:16.443738Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::52
2023-01-19T10:37:16.443745Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.443752Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.443758Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.444511Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3521001,
    events_root: None,
}
2023-01-19T10:37:16.444539Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 53
2023-01-19T10:37:16.444568Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::53
2023-01-19T10:37:16.444575Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.444581Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.444587Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.445436Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3395045,
    events_root: None,
}
2023-01-19T10:37:16.445465Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 54
2023-01-19T10:37:16.445494Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::54
2023-01-19T10:37:16.445501Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.445508Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.445514Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.446270Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3532981,
    events_root: None,
}
2023-01-19T10:37:16.446298Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 55
2023-01-19T10:37:16.446333Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::55
2023-01-19T10:37:16.446344Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.446355Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.446364Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.447252Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3407025,
    events_root: None,
}
2023-01-19T10:37:16.447281Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 56
2023-01-19T10:37:16.447309Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::56
2023-01-19T10:37:16.447316Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.447323Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.447329Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.448084Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3535377,
    events_root: None,
}
2023-01-19T10:37:16.448111Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 57
2023-01-19T10:37:16.448140Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::57
2023-01-19T10:37:16.448147Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.448153Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.448159Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.449004Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3409421,
    events_root: None,
}
2023-01-19T10:37:16.449033Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 58
2023-01-19T10:37:16.449062Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::58
2023-01-19T10:37:16.449068Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.449075Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.449081Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.449830Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3521009,
    events_root: None,
}
2023-01-19T10:37:16.449857Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 59
2023-01-19T10:37:16.449886Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::59
2023-01-19T10:37:16.449893Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.449900Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.449906Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.450754Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3395053,
    events_root: None,
}
2023-01-19T10:37:16.450783Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 60
2023-01-19T10:37:16.450811Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::60
2023-01-19T10:37:16.450818Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.450825Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.450831Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.452601Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5691229,
    events_root: None,
}
2023-01-19T10:37:16.452639Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 61
2023-01-19T10:37:16.452668Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::61
2023-01-19T10:37:16.452675Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.452681Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.452687Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.453585Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3368973,
    events_root: None,
}
2023-01-19T10:37:16.453614Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 62
2023-01-19T10:37:16.453642Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::62
2023-01-19T10:37:16.453649Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.453656Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.453662Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.455459Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5716597,
    events_root: None,
}
2023-01-19T10:37:16.455496Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 63
2023-01-19T10:37:16.455525Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::63
2023-01-19T10:37:16.455532Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.455539Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.455544Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.456396Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394341,
    events_root: None,
}
2023-01-19T10:37:16.456425Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 64
2023-01-19T10:37:16.456454Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::64
2023-01-19T10:37:16.456460Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.456467Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.456473Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.458229Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5728577,
    events_root: None,
}
2023-01-19T10:37:16.458267Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 65
2023-01-19T10:37:16.458295Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::65
2023-01-19T10:37:16.458302Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.458309Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.458315Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.459157Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3406321,
    events_root: None,
}
2023-01-19T10:37:16.459186Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 66
2023-01-19T10:37:16.459214Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::66
2023-01-19T10:37:16.459221Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.459228Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.459234Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.461001Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5730973,
    events_root: None,
}
2023-01-19T10:37:16.461039Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 67
2023-01-19T10:37:16.461067Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::67
2023-01-19T10:37:16.461074Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.461081Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.461086Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.461988Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3408717,
    events_root: None,
}
2023-01-19T10:37:16.462017Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 68
2023-01-19T10:37:16.462046Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::68
2023-01-19T10:37:16.462053Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.462060Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.462066Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.463822Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5716605,
    events_root: None,
}
2023-01-19T10:37:16.463865Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 69
2023-01-19T10:37:16.463893Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::69
2023-01-19T10:37:16.463900Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.463907Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.463913Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.464756Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394349,
    events_root: None,
}
2023-01-19T10:37:16.464785Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 70
2023-01-19T10:37:16.464813Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::70
2023-01-19T10:37:16.464820Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.464827Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.464833Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.465768Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3759123,
    events_root: None,
}
2023-01-19T10:37:16.465799Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 71
2023-01-19T10:37:16.465828Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::71
2023-01-19T10:37:16.465834Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.465841Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.465847Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.466683Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3368733,
    events_root: None,
}
2023-01-19T10:37:16.466712Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 72
2023-01-19T10:37:16.466742Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::72
2023-01-19T10:37:16.466750Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.466757Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.466764Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.467701Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3784491,
    events_root: None,
}
2023-01-19T10:37:16.467732Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 73
2023-01-19T10:37:16.467761Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::73
2023-01-19T10:37:16.467767Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.467774Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.467780Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.468625Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394101,
    events_root: None,
}
2023-01-19T10:37:16.468654Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 74
2023-01-19T10:37:16.468683Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::74
2023-01-19T10:37:16.468690Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.468696Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.468702Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.469691Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3796471,
    events_root: None,
}
2023-01-19T10:37:16.469722Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 75
2023-01-19T10:37:16.469752Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::75
2023-01-19T10:37:16.469760Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.469767Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.469774Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.470616Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3406081,
    events_root: None,
}
2023-01-19T10:37:16.470645Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 76
2023-01-19T10:37:16.470674Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::76
2023-01-19T10:37:16.470680Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.470687Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.470693Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.471636Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3798867,
    events_root: None,
}
2023-01-19T10:37:16.471667Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 77
2023-01-19T10:37:16.471696Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::77
2023-01-19T10:37:16.471707Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.471713Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.471719Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.472596Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3408477,
    events_root: None,
}
2023-01-19T10:37:16.472625Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 78
2023-01-19T10:37:16.472653Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::78
2023-01-19T10:37:16.472660Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.472667Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.472672Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.473609Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3784499,
    events_root: None,
}
2023-01-19T10:37:16.473640Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 79
2023-01-19T10:37:16.473668Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::79
2023-01-19T10:37:16.473675Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.473682Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.473688Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.474527Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394109,
    events_root: None,
}
2023-01-19T10:37:16.474555Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 80
2023-01-19T10:37:16.474584Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::80
2023-01-19T10:37:16.474591Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.474597Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.474603Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.476365Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5106865,
    events_root: None,
}
2023-01-19T10:37:16.476415Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 81
2023-01-19T10:37:16.476456Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::81
2023-01-19T10:37:16.476467Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.476477Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.476487Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.478151Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4191846,
    events_root: None,
}
2023-01-19T10:37:16.478189Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 82
2023-01-19T10:37:16.478218Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::82
2023-01-19T10:37:16.478224Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.478231Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.478237Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.479888Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4203826,
    events_root: None,
}
2023-01-19T10:37:16.479926Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 83
2023-01-19T10:37:16.479955Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::83
2023-01-19T10:37:16.479961Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.479968Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.479974Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.481617Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4206222,
    events_root: None,
}
2023-01-19T10:37:16.481655Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 84
2023-01-19T10:37:16.481684Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::London::84
2023-01-19T10:37:16.481691Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.481697Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.481703Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.483344Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4191854,
    events_root: None,
}
2023-01-19T10:37:16.483384Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-19T10:37:16.483413Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::0
2023-01-19T10:37:16.483419Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.483426Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.483432Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.484179Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2864889,
    events_root: None,
}
2023-01-19T10:37:16.484207Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-19T10:37:16.484236Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::1
2023-01-19T10:37:16.484242Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.484249Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.484255Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.484939Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2801386,
    events_root: None,
}
2023-01-19T10:37:16.484966Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-19T10:37:16.484994Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::2
2023-01-19T10:37:16.485001Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.485008Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.485014Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.485755Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2874617,
    events_root: None,
}
2023-01-19T10:37:16.485783Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-19T10:37:16.485812Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::3
2023-01-19T10:37:16.485818Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.485825Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.485831Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.486573Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2826754,
    events_root: None,
}
2023-01-19T10:37:16.486599Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-19T10:37:16.486628Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::4
2023-01-19T10:37:16.486635Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.486641Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.486647Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.487388Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2886597,
    events_root: None,
}
2023-01-19T10:37:16.487415Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-19T10:37:16.487444Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::5
2023-01-19T10:37:16.487450Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.487457Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.487463Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.488156Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2838734,
    events_root: None,
}
2023-01-19T10:37:16.488182Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-19T10:37:16.488211Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::6
2023-01-19T10:37:16.488218Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.488224Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.488230Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.489007Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2888993,
    events_root: None,
}
2023-01-19T10:37:16.489035Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-19T10:37:16.489063Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::7
2023-01-19T10:37:16.489070Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.489077Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.489083Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.489771Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2841130,
    events_root: None,
}
2023-01-19T10:37:16.489798Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 8
2023-01-19T10:37:16.489827Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::8
2023-01-19T10:37:16.489833Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.489840Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.489846Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.490585Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2874625,
    events_root: None,
}
2023-01-19T10:37:16.490613Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 9
2023-01-19T10:37:16.490641Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::9
2023-01-19T10:37:16.490648Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.490655Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.490661Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.491346Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2826762,
    events_root: None,
}
2023-01-19T10:37:16.491373Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 10
2023-01-19T10:37:16.491402Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::10
2023-01-19T10:37:16.491408Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.491415Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.491421Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.492910Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4233379,
    events_root: None,
}
2023-01-19T10:37:16.492945Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 11
2023-01-19T10:37:16.492974Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::11
2023-01-19T10:37:16.492980Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.492987Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.492993Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.493603Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1828927,
    events_root: None,
}
2023-01-19T10:37:16.493628Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 12
2023-01-19T10:37:16.493657Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::12
2023-01-19T10:37:16.493664Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.493671Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.493677Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.495158Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4258747,
    events_root: None,
}
2023-01-19T10:37:16.495192Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 13
2023-01-19T10:37:16.495221Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::13
2023-01-19T10:37:16.495227Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.495234Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.495240Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.495799Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1854295,
    events_root: None,
}
2023-01-19T10:37:16.495828Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 14
2023-01-19T10:37:16.495857Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::14
2023-01-19T10:37:16.495864Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.495870Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.495876Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.497354Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4270727,
    events_root: None,
}
2023-01-19T10:37:16.497388Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 15
2023-01-19T10:37:16.497417Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::15
2023-01-19T10:37:16.497424Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.497431Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.497437Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.498002Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1866275,
    events_root: None,
}
2023-01-19T10:37:16.498027Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 16
2023-01-19T10:37:16.498056Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::16
2023-01-19T10:37:16.498062Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.498069Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.498075Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.499552Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4273123,
    events_root: None,
}
2023-01-19T10:37:16.499586Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 17
2023-01-19T10:37:16.499615Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::17
2023-01-19T10:37:16.499621Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.499628Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.499634Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.500197Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1868671,
    events_root: None,
}
2023-01-19T10:37:16.500222Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 18
2023-01-19T10:37:16.500251Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::18
2023-01-19T10:37:16.500257Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.500264Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.500270Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.501745Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4258755,
    events_root: None,
}
2023-01-19T10:37:16.501780Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 19
2023-01-19T10:37:16.501808Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::19
2023-01-19T10:37:16.501815Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.501822Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.501828Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.502441Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1854303,
    events_root: None,
}
2023-01-19T10:37:16.502466Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 20
2023-01-19T10:37:16.502495Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::20
2023-01-19T10:37:16.502501Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.502508Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.502514Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.503994Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4236828,
    events_root: None,
}
2023-01-19T10:37:16.504029Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 21
2023-01-19T10:37:16.504058Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::21
2023-01-19T10:37:16.504064Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.504071Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.504077Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.504633Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1831217,
    events_root: None,
}
2023-01-19T10:37:16.504658Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 22
2023-01-19T10:37:16.504687Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::22
2023-01-19T10:37:16.504693Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.504700Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.504706Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.506231Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4262196,
    events_root: None,
}
2023-01-19T10:37:16.506265Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 23
2023-01-19T10:37:16.506294Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::23
2023-01-19T10:37:16.506300Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.506307Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.506313Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.506873Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1856585,
    events_root: None,
}
2023-01-19T10:37:16.506898Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 24
2023-01-19T10:37:16.506927Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::24
2023-01-19T10:37:16.506934Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.506940Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.506946Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.508430Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4274176,
    events_root: None,
}
2023-01-19T10:37:16.508464Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 25
2023-01-19T10:37:16.508493Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::25
2023-01-19T10:37:16.508500Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.508507Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.508512Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.509072Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1868565,
    events_root: None,
}
2023-01-19T10:37:16.509097Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 26
2023-01-19T10:37:16.509126Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::26
2023-01-19T10:37:16.509133Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.509140Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.509146Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.510625Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4276572,
    events_root: None,
}
2023-01-19T10:37:16.510659Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 27
2023-01-19T10:37:16.510695Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::27
2023-01-19T10:37:16.510706Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.510716Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.510725Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.511330Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1870961,
    events_root: None,
}
2023-01-19T10:37:16.511355Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 28
2023-01-19T10:37:16.511383Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::28
2023-01-19T10:37:16.511390Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.511396Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.511402Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.512894Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4262204,
    events_root: None,
}
2023-01-19T10:37:16.512928Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 29
2023-01-19T10:37:16.512957Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::29
2023-01-19T10:37:16.512964Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.512970Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.512976Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.513531Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1856593,
    events_root: None,
}
2023-01-19T10:37:16.513556Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 30
2023-01-19T10:37:16.513585Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::30
2023-01-19T10:37:16.513592Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.513598Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.513604Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.515152Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4739573,
    events_root: None,
}
2023-01-19T10:37:16.515186Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 31
2023-01-19T10:37:16.515215Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::31
2023-01-19T10:37:16.515222Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.515228Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.515234Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.515921Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2818071,
    events_root: None,
}
2023-01-19T10:37:16.515948Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 32
2023-01-19T10:37:16.515977Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::32
2023-01-19T10:37:16.515983Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.515990Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.515997Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.517543Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4780398,
    events_root: None,
}
2023-01-19T10:37:16.517578Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 33
2023-01-19T10:37:16.517606Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::33
2023-01-19T10:37:16.517613Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.517620Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.517625Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.518312Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2843439,
    events_root: None,
}
2023-01-19T10:37:16.518339Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 34
2023-01-19T10:37:16.518367Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::34
2023-01-19T10:37:16.518374Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.518381Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.518386Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.519940Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4792378,
    events_root: None,
}
2023-01-19T10:37:16.519983Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 35
2023-01-19T10:37:16.520025Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::35
2023-01-19T10:37:16.520035Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.520046Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.520055Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.520775Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2855419,
    events_root: None,
}
2023-01-19T10:37:16.520802Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 36
2023-01-19T10:37:16.520831Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::36
2023-01-19T10:37:16.520837Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.520844Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.520850Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.522429Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4794774,
    events_root: None,
}
2023-01-19T10:37:16.522464Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 37
2023-01-19T10:37:16.522492Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::37
2023-01-19T10:37:16.522499Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.522506Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.522512Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.523198Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2857815,
    events_root: None,
}
2023-01-19T10:37:16.523225Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 38
2023-01-19T10:37:16.523253Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::38
2023-01-19T10:37:16.523260Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.523266Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.523272Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.524819Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4780406,
    events_root: None,
}
2023-01-19T10:37:16.524854Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 39
2023-01-19T10:37:16.524883Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::39
2023-01-19T10:37:16.524890Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.524896Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.524902Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.525589Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2843447,
    events_root: None,
}
2023-01-19T10:37:16.525616Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 40
2023-01-19T10:37:16.525644Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::40
2023-01-19T10:37:16.525651Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.525658Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.525664Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.526638Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3888701,
    events_root: None,
}
2023-01-19T10:37:16.526670Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 41
2023-01-19T10:37:16.526698Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::41
2023-01-19T10:37:16.526705Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.526712Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.526718Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.527559Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3369197,
    events_root: None,
}
2023-01-19T10:37:16.527587Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 42
2023-01-19T10:37:16.527616Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::42
2023-01-19T10:37:16.527622Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.527629Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.527638Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.528669Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3830685,
    events_root: None,
}
2023-01-19T10:37:16.528700Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 43
2023-01-19T10:37:16.528729Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::43
2023-01-19T10:37:16.528736Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.528742Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.528748Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.529589Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394565,
    events_root: None,
}
2023-01-19T10:37:16.529618Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 44
2023-01-19T10:37:16.529647Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::44
2023-01-19T10:37:16.529654Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.529660Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.529666Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.530640Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3842665,
    events_root: None,
}
2023-01-19T10:37:16.530672Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 45
2023-01-19T10:37:16.530700Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::45
2023-01-19T10:37:16.530707Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.530714Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.530720Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.531559Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3406545,
    events_root: None,
}
2023-01-19T10:37:16.531587Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 46
2023-01-19T10:37:16.531616Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::46
2023-01-19T10:37:16.531622Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.531629Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.531635Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.532605Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3845061,
    events_root: None,
}
2023-01-19T10:37:16.532636Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 47
2023-01-19T10:37:16.532665Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::47
2023-01-19T10:37:16.532672Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.532678Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.532684Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.533531Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3408941,
    events_root: None,
}
2023-01-19T10:37:16.533560Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 48
2023-01-19T10:37:16.533589Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::48
2023-01-19T10:37:16.533596Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.533602Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.533608Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.534577Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3830693,
    events_root: None,
}
2023-01-19T10:37:16.534614Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 49
2023-01-19T10:37:16.534656Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::49
2023-01-19T10:37:16.534666Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.534677Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.534686Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: Call, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.535552Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394573,
    events_root: None,
}
2023-01-19T10:37:16.535581Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 50
2023-01-19T10:37:16.535610Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::50
2023-01-19T10:37:16.535616Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.535623Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.535629Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.536377Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3495633,
    events_root: None,
}
2023-01-19T10:37:16.536404Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 51
2023-01-19T10:37:16.536433Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::51
2023-01-19T10:37:16.536439Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.536446Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.536452Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.537287Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3369677,
    events_root: None,
}
2023-01-19T10:37:16.537316Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 52
2023-01-19T10:37:16.537345Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::52
2023-01-19T10:37:16.537351Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.537358Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.537364Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.538111Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3521001,
    events_root: None,
}
2023-01-19T10:37:16.538139Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 53
2023-01-19T10:37:16.538167Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::53
2023-01-19T10:37:16.538174Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.538181Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.538186Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.539060Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3395045,
    events_root: None,
}
2023-01-19T10:37:16.539089Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 54
2023-01-19T10:37:16.539118Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::54
2023-01-19T10:37:16.539124Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.539131Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.539137Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.539887Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3532981,
    events_root: None,
}
2023-01-19T10:37:16.539915Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 55
2023-01-19T10:37:16.539943Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::55
2023-01-19T10:37:16.539950Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.539957Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.539962Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.540851Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3407025,
    events_root: None,
}
2023-01-19T10:37:16.540880Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 56
2023-01-19T10:37:16.540909Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::56
2023-01-19T10:37:16.540915Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.540922Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.540928Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.541674Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3535377,
    events_root: None,
}
2023-01-19T10:37:16.541701Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 57
2023-01-19T10:37:16.541730Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::57
2023-01-19T10:37:16.541737Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.541743Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.541749Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.542593Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3409421,
    events_root: None,
}
2023-01-19T10:37:16.542622Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 58
2023-01-19T10:37:16.542650Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::58
2023-01-19T10:37:16.542657Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.542664Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.542670Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.543419Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3521009,
    events_root: None,
}
2023-01-19T10:37:16.543446Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 59
2023-01-19T10:37:16.543475Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::59
2023-01-19T10:37:16.543481Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.543488Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.543494Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: CallCode, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.544342Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3395053,
    events_root: None,
}
2023-01-19T10:37:16.544371Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 60
2023-01-19T10:37:16.544400Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::60
2023-01-19T10:37:16.544407Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.544413Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.544419Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.546173Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5691229,
    events_root: None,
}
2023-01-19T10:37:16.546211Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 61
2023-01-19T10:37:16.546240Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::61
2023-01-19T10:37:16.546246Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.546253Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.546259Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.547097Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3368973,
    events_root: None,
}
2023-01-19T10:37:16.547132Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 62
2023-01-19T10:37:16.547173Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::62
2023-01-19T10:37:16.547184Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.547194Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.547203Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.548985Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5716597,
    events_root: None,
}
2023-01-19T10:37:16.549022Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 63
2023-01-19T10:37:16.549051Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::63
2023-01-19T10:37:16.549058Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.549065Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.549071Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.549913Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394341,
    events_root: None,
}
2023-01-19T10:37:16.549941Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 64
2023-01-19T10:37:16.549970Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::64
2023-01-19T10:37:16.549977Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.549984Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.549989Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.551741Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5728577,
    events_root: None,
}
2023-01-19T10:37:16.551779Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 65
2023-01-19T10:37:16.551808Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::65
2023-01-19T10:37:16.551815Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.551821Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.551833Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.552687Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3406321,
    events_root: None,
}
2023-01-19T10:37:16.552716Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 66
2023-01-19T10:37:16.552744Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::66
2023-01-19T10:37:16.552751Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.552758Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.552763Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.554521Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5730973,
    events_root: None,
}
2023-01-19T10:37:16.554558Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 67
2023-01-19T10:37:16.554587Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::67
2023-01-19T10:37:16.554594Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.554600Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.554606Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.555482Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3408717,
    events_root: None,
}
2023-01-19T10:37:16.555511Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 68
2023-01-19T10:37:16.555539Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::68
2023-01-19T10:37:16.555546Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.555552Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.555558Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 0
[DEBUG] fetching parameters block: 0
2023-01-19T10:37:16.557360Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5716605,
    events_root: None,
}
2023-01-19T10:37:16.557397Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 69
2023-01-19T10:37:16.557426Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::69
2023-01-19T10:37:16.557433Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.557439Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.557445Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: DelegateCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.558290Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394349,
    events_root: None,
}
2023-01-19T10:37:16.558319Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 70
2023-01-19T10:37:16.558348Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::70
2023-01-19T10:37:16.558355Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.558361Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.558367Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.559301Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3759123,
    events_root: None,
}
2023-01-19T10:37:16.559332Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 71
2023-01-19T10:37:16.559360Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::71
2023-01-19T10:37:16.559367Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.559373Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.559379Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.560223Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3368733,
    events_root: None,
}
2023-01-19T10:37:16.560252Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 72
2023-01-19T10:37:16.560280Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::72
2023-01-19T10:37:16.560287Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.560294Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.560300Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.561238Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3784491,
    events_root: None,
}
2023-01-19T10:37:16.561269Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 73
2023-01-19T10:37:16.561298Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::73
2023-01-19T10:37:16.561304Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.561311Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.561317Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.562156Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394101,
    events_root: None,
}
2023-01-19T10:37:16.562185Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 74
2023-01-19T10:37:16.562213Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::74
2023-01-19T10:37:16.562220Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.562227Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.562232Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.563170Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3796471,
    events_root: None,
}
2023-01-19T10:37:16.563207Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 75
2023-01-19T10:37:16.563248Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::75
2023-01-19T10:37:16.563259Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.563269Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.563278Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.564150Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3406081,
    events_root: None,
}
2023-01-19T10:37:16.564179Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 76
2023-01-19T10:37:16.564208Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::76
2023-01-19T10:37:16.564215Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.564221Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.564227Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.565165Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3798867,
    events_root: None,
}
2023-01-19T10:37:16.565196Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 77
2023-01-19T10:37:16.565225Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::77
2023-01-19T10:37:16.565232Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.565239Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.565245Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.566085Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3408477,
    events_root: None,
}
2023-01-19T10:37:16.566114Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 78
2023-01-19T10:37:16.566143Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::78
2023-01-19T10:37:16.566149Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.566156Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.566162Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.567098Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3784499,
    events_root: None,
}
2023-01-19T10:37:16.567129Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 79
2023-01-19T10:37:16.567158Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::79
2023-01-19T10:37:16.567164Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.567171Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.567177Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
[INFO] Calling Precompile:
	address: 0000000000000000000000000000000000000002
	context: PrecompileContext { call_type: StaticCall, gas_limit: 4096 }
	input: 0000000000000000000000000000000000000000000000000000000000000002
2023-01-19T10:37:16.568057Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3394109,
    events_root: None,
}
2023-01-19T10:37:16.568088Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 80
2023-01-19T10:37:16.568117Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::80
2023-01-19T10:37:16.568123Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.568130Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.568136Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.569898Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5106865,
    events_root: None,
}
2023-01-19T10:37:16.569938Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 81
2023-01-19T10:37:16.569966Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::81
2023-01-19T10:37:16.569973Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.569979Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.569985Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.571681Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4191846,
    events_root: None,
}
2023-01-19T10:37:16.571719Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 82
2023-01-19T10:37:16.571752Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::82
2023-01-19T10:37:16.571759Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.571765Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.571771Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.573505Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4203826,
    events_root: None,
}
2023-01-19T10:37:16.573543Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 83
2023-01-19T10:37:16.573571Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::83
2023-01-19T10:37:16.573578Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.573585Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.573590Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.575230Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4206222,
    events_root: None,
}
2023-01-19T10:37:16.575267Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 84
2023-01-19T10:37:16.575296Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "invalidAddr"::Merge::84
2023-01-19T10:37:16.575302Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.575309Z  INFO evm_eth_compliance::statetest::runner: TX len : 100
2023-01-19T10:37:16.575315Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-19T10:37:16.576963Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4191854,
    events_root: None,
}
2023-01-19T10:37:16.579016Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stBadOpcode/invalidAddr.json"
2023-01-19T10:37:16.579423Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:12.22036985s
```