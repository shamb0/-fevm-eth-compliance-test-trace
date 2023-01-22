> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| OK | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1.json \
	cargo run \
	-- \
	statetest
```


> Execution Trace

```
2023-01-20T09:38:17.636754Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1.json", Total Files :: 1
2023-01-20T09:38:17.637212Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1.json"
2023-01-20T09:38:17.754659Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-20T09:38:29.851852Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-20T09:38:29.852078Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T09:38:29.852171Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [185, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzacecsquj7xh4vk2t3fxpfxek3wh4jdtmd7u5en66azvnwf7l4u47cl6
[DEBUG] fetching parameters block: 1
2023-01-20T09:38:29.855578Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-20T09:38:29.855722Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T09:38:29.856919Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-20T09:38:29.856983Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1"::Berlin::0
2023-01-20T09:38:29.857000Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1.json"
2023-01-20T09:38:29.857011Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T09:38:29.857020Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:38:29.858288Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3805926,
    events_root: None,
}
2023-01-20T09:38:29.858325Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-20T09:38:29.858353Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1"::Berlin::1
2023-01-20T09:38:29.858360Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1.json"
2023-01-20T09:38:29.858367Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T09:38:29.858373Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:38:29.859420Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908967,
    events_root: None,
}
2023-01-20T09:38:29.859452Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-20T09:38:29.859480Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1"::Berlin::2
2023-01-20T09:38:29.859488Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1.json"
2023-01-20T09:38:29.859494Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T09:38:29.859500Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:38:29.860545Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908967,
    events_root: None,
}
2023-01-20T09:38:29.860576Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-20T09:38:29.860605Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1"::Berlin::3
2023-01-20T09:38:29.860611Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1.json"
2023-01-20T09:38:29.860619Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T09:38:29.860625Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:38:29.861669Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908967,
    events_root: None,
}
2023-01-20T09:38:29.861702Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-20T09:38:29.861730Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1"::London::0
2023-01-20T09:38:29.861737Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1.json"
2023-01-20T09:38:29.861745Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T09:38:29.861751Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:38:29.862797Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908967,
    events_root: None,
}
2023-01-20T09:38:29.862831Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-20T09:38:29.862861Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1"::London::1
2023-01-20T09:38:29.862869Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1.json"
2023-01-20T09:38:29.862879Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T09:38:29.862887Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:38:29.863945Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908967,
    events_root: None,
}
2023-01-20T09:38:29.863982Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-20T09:38:29.864013Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1"::London::2
2023-01-20T09:38:29.864021Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1.json"
2023-01-20T09:38:29.864029Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T09:38:29.864038Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:38:29.865100Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908967,
    events_root: None,
}
2023-01-20T09:38:29.865134Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-20T09:38:29.865165Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1"::London::3
2023-01-20T09:38:29.865172Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1.json"
2023-01-20T09:38:29.865181Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T09:38:29.865189Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:38:29.866243Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908967,
    events_root: None,
}
2023-01-20T09:38:29.866279Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-20T09:38:29.866312Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1"::Merge::0
2023-01-20T09:38:29.866322Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1.json"
2023-01-20T09:38:29.866331Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T09:38:29.866339Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:38:29.867390Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908967,
    events_root: None,
}
2023-01-20T09:38:29.867425Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-20T09:38:29.867455Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1"::Merge::1
2023-01-20T09:38:29.867463Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1.json"
2023-01-20T09:38:29.867472Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T09:38:29.867481Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:38:29.868531Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908967,
    events_root: None,
}
2023-01-20T09:38:29.868565Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-20T09:38:29.868595Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1"::Merge::2
2023-01-20T09:38:29.868603Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1.json"
2023-01-20T09:38:29.868612Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T09:38:29.868621Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:38:29.869697Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908967,
    events_root: None,
}
2023-01-20T09:38:29.869731Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-20T09:38:29.869762Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1"::Merge::3
2023-01-20T09:38:29.869770Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1.json"
2023-01-20T09:38:29.869779Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T09:38:29.869786Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:38:29.870840Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908967,
    events_root: None,
}
2023-01-20T09:38:29.870875Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-20T09:38:29.870905Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1"::Merge::4
2023-01-20T09:38:29.870913Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1.json"
2023-01-20T09:38:29.870922Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:38:29.870929Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:38:29.871974Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2907792,
    events_root: None,
}
2023-01-20T09:38:29.872015Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-20T09:38:29.872047Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1"::Merge::5
2023-01-20T09:38:29.872056Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1.json"
2023-01-20T09:38:29.872066Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:38:29.872073Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:38:29.873132Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2907792,
    events_root: None,
}
2023-01-20T09:38:29.873166Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-20T09:38:29.873196Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1"::Merge::6
2023-01-20T09:38:29.873204Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1.json"
2023-01-20T09:38:29.873213Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T09:38:29.873221Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:38:29.874365Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910951,
    events_root: None,
}
2023-01-20T09:38:29.874411Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-20T09:38:29.874453Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1"::Merge::7
2023-01-20T09:38:29.874462Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1.json"
2023-01-20T09:38:29.874469Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T09:38:29.874476Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:38:29.875929Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910951,
    events_root: None,
}
2023-01-20T09:38:29.875978Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 8
2023-01-20T09:38:29.876026Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1"::Merge::8
2023-01-20T09:38:29.876033Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1.json"
2023-01-20T09:38:29.876040Z  INFO evm_eth_compliance::statetest::runner: TX len : 64
2023-01-20T09:38:29.876046Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:38:29.877160Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910980,
    events_root: None,
}
2023-01-20T09:38:29.877192Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 9
2023-01-20T09:38:29.877220Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1"::Merge::9
2023-01-20T09:38:29.877227Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1.json"
2023-01-20T09:38:29.877234Z  INFO evm_eth_compliance::statetest::runner: TX len : 62
2023-01-20T09:38:29.877239Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:38:29.878281Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910977,
    events_root: None,
}
2023-01-20T09:38:29.878315Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 0
2023-01-20T09:38:29.878344Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1"::Shanghai::0
2023-01-20T09:38:29.878351Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1.json"
2023-01-20T09:38:29.878358Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T09:38:29.878364Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:38:29.879399Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908967,
    events_root: None,
}
2023-01-20T09:38:29.879430Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 1
2023-01-20T09:38:29.879458Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1"::Shanghai::1
2023-01-20T09:38:29.879465Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1.json"
2023-01-20T09:38:29.879472Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T09:38:29.879479Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:38:29.880510Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908967,
    events_root: None,
}
2023-01-20T09:38:29.880542Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 2
2023-01-20T09:38:29.880569Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1"::Shanghai::2
2023-01-20T09:38:29.880577Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1.json"
2023-01-20T09:38:29.880584Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T09:38:29.880590Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:38:29.881656Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908967,
    events_root: None,
}
2023-01-20T09:38:29.881686Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 3
2023-01-20T09:38:29.881714Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1"::Shanghai::3
2023-01-20T09:38:29.881721Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1.json"
2023-01-20T09:38:29.881728Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T09:38:29.881735Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:38:29.882823Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908967,
    events_root: None,
}
2023-01-20T09:38:29.882854Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 4
2023-01-20T09:38:29.882883Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1"::Shanghai::4
2023-01-20T09:38:29.882890Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1.json"
2023-01-20T09:38:29.882897Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:38:29.882903Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:38:29.884097Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2907792,
    events_root: None,
}
2023-01-20T09:38:29.884137Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 5
2023-01-20T09:38:29.884174Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1"::Shanghai::5
2023-01-20T09:38:29.884184Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1.json"
2023-01-20T09:38:29.884194Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:38:29.884202Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:38:29.885437Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909147,
    events_root: None,
}
2023-01-20T09:38:29.885479Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 6
2023-01-20T09:38:29.885518Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1"::Shanghai::6
2023-01-20T09:38:29.885528Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1.json"
2023-01-20T09:38:29.885538Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T09:38:29.885548Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:38:29.886772Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2912404,
    events_root: None,
}
2023-01-20T09:38:29.886803Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 7
2023-01-20T09:38:29.886837Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1"::Shanghai::7
2023-01-20T09:38:29.886845Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1.json"
2023-01-20T09:38:29.886854Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T09:38:29.886862Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:38:29.888025Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2912404,
    events_root: None,
}
2023-01-20T09:38:29.888077Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 8
2023-01-20T09:38:29.888125Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1"::Shanghai::8
2023-01-20T09:38:29.888136Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1.json"
2023-01-20T09:38:29.888146Z  INFO evm_eth_compliance::statetest::runner: TX len : 64
2023-01-20T09:38:29.888155Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:38:29.889517Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2912433,
    events_root: None,
}
2023-01-20T09:38:29.889557Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 9
2023-01-20T09:38:29.889596Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1"::Shanghai::9
2023-01-20T09:38:29.889603Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1.json"
2023-01-20T09:38:29.889611Z  INFO evm_eth_compliance::statetest::runner: TX len : 62
2023-01-20T09:38:29.889617Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:38:29.890777Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2912430,
    events_root: None,
}
2023-01-20T09:38:29.893103Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1.json"
2023-01-20T09:38:29.893455Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:12.136186936s
```