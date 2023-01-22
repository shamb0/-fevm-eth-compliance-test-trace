> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

EIP-3541: Contract code starting with the 0xEF byte is disallowed

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json#L1

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid_FromEOF.json \
	cargo run \
	-- \
	statetest
```

> Execution Trace

```
2023-01-20T09:54:15.183496Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json", Total Files :: 1
2023-01-20T09:54:15.183893Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:15.331007Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [169, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([179, 152, 63, 197, 60, 234, 37, 74, 66, 53, 75, 140, 66, 70, 3, 8, 241, 171, 25, 86]) }
[DEBUG] getting cid: bafy2bzaceaii7gatq5yoovv5j5rn5hvbvdukafhmhnjm36ur627u6hyo6dame
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.284865Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [200]
2023-01-20T09:54:27.285059Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T09:54:27.285137Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [185, 79, 83, 116, 252, 229, 237, 188, 142, 42, 134, 151, 193, 83, 49, 103, 126, 110, 191, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([157, 122, 181, 47, 53, 176, 191, 159, 121, 68, 73, 204, 112, 124, 226, 155, 100, 141, 75, 36]) }
[DEBUG] getting cid: bafy2bzacecsquj7xh4vk2t3fxpfxek3wh4jdtmd7u5en66azvnwf7l4u47cl6
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.288290Z  INFO evm_eth_compliance::statetest::runner: Dummy Place Holder Contract got deployed with Actor ID [201]
2023-01-20T09:54:27.288429Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-20T09:54:27.289631Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-20T09:54:27.289686Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::0
2023-01-20T09:54:27.289695Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.289704Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-20T09:54:27.289711Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.290933Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3805795,
    events_root: None,
}
2023-01-20T09:54:27.290970Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-20T09:54:27.290998Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::1
2023-01-20T09:54:27.291005Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.291012Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T09:54:27.291018Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.292049Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910951,
    events_root: None,
}
2023-01-20T09:54:27.292080Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-20T09:54:27.292109Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::2
2023-01-20T09:54:27.292116Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.292124Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T09:54:27.292130Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.293169Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910951,
    events_root: None,
}
2023-01-20T09:54:27.293200Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-20T09:54:27.293228Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::3
2023-01-20T09:54:27.293235Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.293242Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T09:54:27.293247Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.294272Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910951,
    events_root: None,
}
2023-01-20T09:54:27.294302Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 4
2023-01-20T09:54:27.294330Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::4
2023-01-20T09:54:27.294337Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.294344Z  INFO evm_eth_compliance::statetest::runner: TX len : 2
2023-01-20T09:54:27.294350Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.295370Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908850,
    events_root: None,
}
2023-01-20T09:54:27.295401Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 5
2023-01-20T09:54:27.295430Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::5
2023-01-20T09:54:27.295437Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.295444Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T09:54:27.295449Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.296815Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910951,
    events_root: None,
}
2023-01-20T09:54:27.296850Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 6
2023-01-20T09:54:27.296885Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::6
2023-01-20T09:54:27.296892Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.296899Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T09:54:27.296905Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.297973Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910951,
    events_root: None,
}
2023-01-20T09:54:27.298004Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 7
2023-01-20T09:54:27.298032Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::7
2023-01-20T09:54:27.298040Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.298048Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T09:54:27.298054Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.299149Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910951,
    events_root: None,
}
2023-01-20T09:54:27.299180Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 8
2023-01-20T09:54:27.299209Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::8
2023-01-20T09:54:27.299216Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.299223Z  INFO evm_eth_compliance::statetest::runner: TX len : 3
2023-01-20T09:54:27.299229Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.300252Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908863,
    events_root: None,
}
2023-01-20T09:54:27.300282Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 9
2023-01-20T09:54:27.300311Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::9
2023-01-20T09:54:27.300318Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.300324Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T09:54:27.300330Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.301356Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908876,
    events_root: None,
}
2023-01-20T09:54:27.301387Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 10
2023-01-20T09:54:27.301415Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::10
2023-01-20T09:54:27.301422Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.301429Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T09:54:27.301435Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.302477Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908876,
    events_root: None,
}
2023-01-20T09:54:27.302508Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 11
2023-01-20T09:54:27.302538Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::11
2023-01-20T09:54:27.302545Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.302552Z  INFO evm_eth_compliance::statetest::runner: TX len : 5
2023-01-20T09:54:27.302559Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.303580Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908901,
    events_root: None,
}
2023-01-20T09:54:27.303611Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 12
2023-01-20T09:54:27.303639Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::12
2023-01-20T09:54:27.303646Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.303653Z  INFO evm_eth_compliance::statetest::runner: TX len : 7
2023-01-20T09:54:27.303659Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.304675Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908928,
    events_root: None,
}
2023-01-20T09:54:27.304706Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 13
2023-01-20T09:54:27.304743Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::13
2023-01-20T09:54:27.304752Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.304759Z  INFO evm_eth_compliance::statetest::runner: TX len : 8
2023-01-20T09:54:27.304765Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.305802Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908941,
    events_root: None,
}
2023-01-20T09:54:27.305831Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 14
2023-01-20T09:54:27.305860Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::14
2023-01-20T09:54:27.305867Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.305874Z  INFO evm_eth_compliance::statetest::runner: TX len : 9
2023-01-20T09:54:27.305880Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.306910Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908954,
    events_root: None,
}
2023-01-20T09:54:27.306940Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 15
2023-01-20T09:54:27.306969Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::15
2023-01-20T09:54:27.306976Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.306983Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T09:54:27.306989Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.308008Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908967,
    events_root: None,
}
2023-01-20T09:54:27.308038Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 16
2023-01-20T09:54:27.308066Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::16
2023-01-20T09:54:27.308075Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.308082Z  INFO evm_eth_compliance::statetest::runner: TX len : 11
2023-01-20T09:54:27.308088Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.309146Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908981,
    events_root: None,
}
2023-01-20T09:54:27.309176Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 17
2023-01-20T09:54:27.309203Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::17
2023-01-20T09:54:27.309211Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.309218Z  INFO evm_eth_compliance::statetest::runner: TX len : 14
2023-01-20T09:54:27.309224Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.310231Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908444,
    events_root: None,
}
2023-01-20T09:54:27.310261Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 18
2023-01-20T09:54:27.310289Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::18
2023-01-20T09:54:27.310296Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.310303Z  INFO evm_eth_compliance::statetest::runner: TX len : 19
2023-01-20T09:54:27.310309Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.311315Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908510,
    events_root: None,
}
2023-01-20T09:54:27.311348Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 19
2023-01-20T09:54:27.311375Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::19
2023-01-20T09:54:27.311382Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.311389Z  INFO evm_eth_compliance::statetest::runner: TX len : 19
2023-01-20T09:54:27.311395Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.312404Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908510,
    events_root: None,
}
2023-01-20T09:54:27.312434Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 20
2023-01-20T09:54:27.312462Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::20
2023-01-20T09:54:27.312469Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.312476Z  INFO evm_eth_compliance::statetest::runner: TX len : 17
2023-01-20T09:54:27.312481Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.313507Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908484,
    events_root: None,
}
2023-01-20T09:54:27.313537Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 21
2023-01-20T09:54:27.313566Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::21
2023-01-20T09:54:27.313572Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.313579Z  INFO evm_eth_compliance::statetest::runner: TX len : 15
2023-01-20T09:54:27.313585Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.314600Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908457,
    events_root: None,
}
2023-01-20T09:54:27.314630Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 22
2023-01-20T09:54:27.314659Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::22
2023-01-20T09:54:27.314666Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.314673Z  INFO evm_eth_compliance::statetest::runner: TX len : 13
2023-01-20T09:54:27.314678Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.315685Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908431,
    events_root: None,
}
2023-01-20T09:54:27.315715Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 23
2023-01-20T09:54:27.315743Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::23
2023-01-20T09:54:27.315750Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.315757Z  INFO evm_eth_compliance::statetest::runner: TX len : 19
2023-01-20T09:54:27.315763Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.316770Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909865,
    events_root: None,
}
2023-01-20T09:54:27.316800Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 24
2023-01-20T09:54:27.316828Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::24
2023-01-20T09:54:27.316835Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.316843Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T09:54:27.316849Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.317867Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909240,
    events_root: None,
}
2023-01-20T09:54:27.317898Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 25
2023-01-20T09:54:27.317925Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::25
2023-01-20T09:54:27.317932Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.317940Z  INFO evm_eth_compliance::statetest::runner: TX len : 27
2023-01-20T09:54:27.317946Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.318955Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2914863,
    events_root: None,
}
2023-01-20T09:54:27.318986Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 26
2023-01-20T09:54:27.319013Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::26
2023-01-20T09:54:27.319020Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.319027Z  INFO evm_eth_compliance::statetest::runner: TX len : 19
2023-01-20T09:54:27.319033Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.320077Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909963,
    events_root: None,
}
2023-01-20T09:54:27.320107Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 27
2023-01-20T09:54:27.320135Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::27
2023-01-20T09:54:27.320143Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.320150Z  INFO evm_eth_compliance::statetest::runner: TX len : 19
2023-01-20T09:54:27.320156Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.321396Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909963,
    events_root: None,
}
2023-01-20T09:54:27.321441Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 28
2023-01-20T09:54:27.321492Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::28
2023-01-20T09:54:27.321505Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.321516Z  INFO evm_eth_compliance::statetest::runner: TX len : 13
2023-01-20T09:54:27.321525Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.322667Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909884,
    events_root: None,
}
2023-01-20T09:54:27.322698Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 29
2023-01-20T09:54:27.322726Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::29
2023-01-20T09:54:27.322732Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.322739Z  INFO evm_eth_compliance::statetest::runner: TX len : 21
2023-01-20T09:54:27.322745Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.323762Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909253,
    events_root: None,
}
2023-01-20T09:54:27.323792Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 30
2023-01-20T09:54:27.323821Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::30
2023-01-20T09:54:27.323828Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.323835Z  INFO evm_eth_compliance::statetest::runner: TX len : 22
2023-01-20T09:54:27.323840Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.324868Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909267,
    events_root: None,
}
2023-01-20T09:54:27.324900Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 31
2023-01-20T09:54:27.324927Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::31
2023-01-20T09:54:27.324934Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.324941Z  INFO evm_eth_compliance::statetest::runner: TX len : 22
2023-01-20T09:54:27.324947Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.325971Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909267,
    events_root: None,
}
2023-01-20T09:54:27.326002Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 32
2023-01-20T09:54:27.326031Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::32
2023-01-20T09:54:27.326038Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.326045Z  INFO evm_eth_compliance::statetest::runner: TX len : 22
2023-01-20T09:54:27.326051Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.327071Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909267,
    events_root: None,
}
2023-01-20T09:54:27.327102Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 33
2023-01-20T09:54:27.327129Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::33
2023-01-20T09:54:27.327136Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.327143Z  INFO evm_eth_compliance::statetest::runner: TX len : 16
2023-01-20T09:54:27.327149Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.328165Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909923,
    events_root: None,
}
2023-01-20T09:54:27.328196Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 34
2023-01-20T09:54:27.328223Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::34
2023-01-20T09:54:27.328230Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.328237Z  INFO evm_eth_compliance::statetest::runner: TX len : 17
2023-01-20T09:54:27.328243Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.329328Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909937,
    events_root: None,
}
2023-01-20T09:54:27.329370Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 35
2023-01-20T09:54:27.329401Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::35
2023-01-20T09:54:27.329408Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.329416Z  INFO evm_eth_compliance::statetest::runner: TX len : 12
2023-01-20T09:54:27.329422Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.330584Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909859,
    events_root: None,
}
2023-01-20T09:54:27.330614Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 36
2023-01-20T09:54:27.330643Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::36
2023-01-20T09:54:27.330649Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.330657Z  INFO evm_eth_compliance::statetest::runner: TX len : 13
2023-01-20T09:54:27.330662Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.331677Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909884,
    events_root: None,
}
2023-01-20T09:54:27.331707Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 37
2023-01-20T09:54:27.331735Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::37
2023-01-20T09:54:27.331742Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.331749Z  INFO evm_eth_compliance::statetest::runner: TX len : 14
2023-01-20T09:54:27.331755Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.332770Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909897,
    events_root: None,
}
2023-01-20T09:54:27.332805Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 38
2023-01-20T09:54:27.332834Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::38
2023-01-20T09:54:27.332841Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.332848Z  INFO evm_eth_compliance::statetest::runner: TX len : 21
2023-01-20T09:54:27.332854Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.334128Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909253,
    events_root: None,
}
2023-01-20T09:54:27.334178Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 39
2023-01-20T09:54:27.334229Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::39
2023-01-20T09:54:27.334242Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.334253Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T09:54:27.334263Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.335343Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909240,
    events_root: None,
}
2023-01-20T09:54:27.335374Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 40
2023-01-20T09:54:27.335402Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::40
2023-01-20T09:54:27.335409Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.335416Z  INFO evm_eth_compliance::statetest::runner: TX len : 23
2023-01-20T09:54:27.335422Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.336437Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909280,
    events_root: None,
}
2023-01-20T09:54:27.336469Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 41
2023-01-20T09:54:27.336498Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::41
2023-01-20T09:54:27.336505Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.336512Z  INFO evm_eth_compliance::statetest::runner: TX len : 25
2023-01-20T09:54:27.336518Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.337552Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909513,
    events_root: None,
}
2023-01-20T09:54:27.337582Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 42
2023-01-20T09:54:27.337610Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::42
2023-01-20T09:54:27.337617Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.337624Z  INFO evm_eth_compliance::statetest::runner: TX len : 27
2023-01-20T09:54:27.337630Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.338657Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2914863,
    events_root: None,
}
2023-01-20T09:54:27.338688Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 43
2023-01-20T09:54:27.338716Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::43
2023-01-20T09:54:27.338723Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.338730Z  INFO evm_eth_compliance::statetest::runner: TX len : 34
2023-01-20T09:54:27.338738Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.339788Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2912785,
    events_root: None,
}
2023-01-20T09:54:27.339819Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 44
2023-01-20T09:54:27.339848Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::44
2023-01-20T09:54:27.339855Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.339862Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T09:54:27.339868Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.340925Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910420,
    events_root: None,
}
2023-01-20T09:54:27.340970Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 45
2023-01-20T09:54:27.341007Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::45
2023-01-20T09:54:27.341015Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.341023Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T09:54:27.341029Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.342156Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910420,
    events_root: None,
}
2023-01-20T09:54:27.342188Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 46
2023-01-20T09:54:27.342216Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::46
2023-01-20T09:54:27.342223Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.342231Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T09:54:27.342237Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.343254Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910420,
    events_root: None,
}
2023-01-20T09:54:27.343285Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 47
2023-01-20T09:54:27.343314Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::47
2023-01-20T09:54:27.343321Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.343329Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T09:54:27.343335Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.344350Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909240,
    events_root: None,
}
2023-01-20T09:54:27.344381Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 48
2023-01-20T09:54:27.344408Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::48
2023-01-20T09:54:27.344415Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.344422Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T09:54:27.344429Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.345466Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909240,
    events_root: None,
}
2023-01-20T09:54:27.345496Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 49
2023-01-20T09:54:27.345524Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::49
2023-01-20T09:54:27.345531Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.345538Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T09:54:27.345544Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.346671Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909240,
    events_root: None,
}
2023-01-20T09:54:27.346730Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 50
2023-01-20T09:54:27.346780Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::50
2023-01-20T09:54:27.346800Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.346825Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T09:54:27.346841Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.348206Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909240,
    events_root: None,
}
2023-01-20T09:54:27.348263Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 51
2023-01-20T09:54:27.348310Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::51
2023-01-20T09:54:27.348330Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.348342Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T09:54:27.348350Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.349715Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909240,
    events_root: None,
}
2023-01-20T09:54:27.349771Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 52
2023-01-20T09:54:27.349820Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::52
2023-01-20T09:54:27.349843Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.349861Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T09:54:27.349875Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.351247Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909240,
    events_root: None,
}
2023-01-20T09:54:27.351303Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 53
2023-01-20T09:54:27.351350Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::53
2023-01-20T09:54:27.351370Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.351387Z  INFO evm_eth_compliance::statetest::runner: TX len : 24
2023-01-20T09:54:27.351403Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.352756Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909500,
    events_root: None,
}
2023-01-20T09:54:27.352816Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 54
2023-01-20T09:54:27.352856Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::54
2023-01-20T09:54:27.352870Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.352891Z  INFO evm_eth_compliance::statetest::runner: TX len : 24
2023-01-20T09:54:27.352907Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.354041Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909500,
    events_root: None,
}
2023-01-20T09:54:27.354075Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 55
2023-01-20T09:54:27.354104Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::55
2023-01-20T09:54:27.354111Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.354118Z  INFO evm_eth_compliance::statetest::runner: TX len : 24
2023-01-20T09:54:27.354124Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.355213Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909500,
    events_root: None,
}
2023-01-20T09:54:27.355249Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 56
2023-01-20T09:54:27.355283Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::56
2023-01-20T09:54:27.355291Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.355298Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T09:54:27.355304Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.356362Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910420,
    events_root: None,
}
2023-01-20T09:54:27.356393Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 57
2023-01-20T09:54:27.356422Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::57
2023-01-20T09:54:27.356428Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.356435Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.356441Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.357501Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.357533Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 58
2023-01-20T09:54:27.357563Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::58
2023-01-20T09:54:27.357570Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.357576Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.357582Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.358614Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.358647Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 59
2023-01-20T09:54:27.358674Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::59
2023-01-20T09:54:27.358681Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.358688Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.358694Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.359758Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.359791Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 60
2023-01-20T09:54:27.359824Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::60
2023-01-20T09:54:27.359831Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.359839Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.359845Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.360997Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.361035Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 61
2023-01-20T09:54:27.361072Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::61
2023-01-20T09:54:27.361079Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.361087Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.361093Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.362152Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.362183Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 62
2023-01-20T09:54:27.362213Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::62
2023-01-20T09:54:27.362222Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.362229Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.362235Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.363257Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.363288Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 63
2023-01-20T09:54:27.363315Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::63
2023-01-20T09:54:27.363322Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.363329Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.363335Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.364351Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.364382Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 64
2023-01-20T09:54:27.364410Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::64
2023-01-20T09:54:27.364417Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.364424Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.364430Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.365460Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.365493Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 65
2023-01-20T09:54:27.365521Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::65
2023-01-20T09:54:27.365528Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.365535Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.365541Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.366572Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.366603Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 66
2023-01-20T09:54:27.366631Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::66
2023-01-20T09:54:27.366638Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.366646Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.366652Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.367685Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.367716Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 67
2023-01-20T09:54:27.367745Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::67
2023-01-20T09:54:27.367752Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.367759Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.367766Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.368793Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.368823Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 68
2023-01-20T09:54:27.368852Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::68
2023-01-20T09:54:27.368859Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.368866Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.368872Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.369911Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.369943Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 69
2023-01-20T09:54:27.369972Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::69
2023-01-20T09:54:27.369979Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.369986Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.369993Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.371061Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.371092Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 70
2023-01-20T09:54:27.371121Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::70
2023-01-20T09:54:27.371128Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.371135Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.371141Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.372170Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.372202Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 71
2023-01-20T09:54:27.372230Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::71
2023-01-20T09:54:27.372237Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.372244Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.372250Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.373364Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.373399Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 72
2023-01-20T09:54:27.373430Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::72
2023-01-20T09:54:27.373438Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.373447Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.373455Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.374497Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.374533Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 73
2023-01-20T09:54:27.374563Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::73
2023-01-20T09:54:27.374572Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.374582Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.374588Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.375623Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.375654Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 74
2023-01-20T09:54:27.375683Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::74
2023-01-20T09:54:27.375690Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.375697Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.375703Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.376738Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.376772Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 75
2023-01-20T09:54:27.376813Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::75
2023-01-20T09:54:27.376824Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.376834Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.376843Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.378009Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.378046Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 76
2023-01-20T09:54:27.378089Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::76
2023-01-20T09:54:27.378101Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.378112Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.378121Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.379309Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.379342Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 77
2023-01-20T09:54:27.379373Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::77
2023-01-20T09:54:27.379380Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.379387Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.379393Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.380425Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.380456Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 78
2023-01-20T09:54:27.380486Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::78
2023-01-20T09:54:27.380492Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.380500Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.380506Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.381539Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.381581Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 79
2023-01-20T09:54:27.381618Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::79
2023-01-20T09:54:27.381627Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.381634Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.381640Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.382670Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.382701Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 80
2023-01-20T09:54:27.382729Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::80
2023-01-20T09:54:27.382735Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.382742Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.382748Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.383778Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.383808Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 81
2023-01-20T09:54:27.383836Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::81
2023-01-20T09:54:27.383843Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.383850Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.383857Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.384881Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.384912Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 82
2023-01-20T09:54:27.384940Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::82
2023-01-20T09:54:27.384946Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.384959Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.384965Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.385984Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.386014Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 83
2023-01-20T09:54:27.386044Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::83
2023-01-20T09:54:27.386052Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.386059Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.386065Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.387084Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.387115Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 84
2023-01-20T09:54:27.387143Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::84
2023-01-20T09:54:27.387150Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.387157Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.387163Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.388182Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.388213Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 85
2023-01-20T09:54:27.388241Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::85
2023-01-20T09:54:27.388248Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.388255Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.388261Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.389283Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.389316Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 86
2023-01-20T09:54:27.389343Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::86
2023-01-20T09:54:27.389351Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.389359Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.389365Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.390384Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.390414Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 87
2023-01-20T09:54:27.390441Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::87
2023-01-20T09:54:27.390449Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.390456Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.390462Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.391576Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.391619Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 88
2023-01-20T09:54:27.391663Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::88
2023-01-20T09:54:27.391674Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.391685Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.391694Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.392789Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.392823Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 89
2023-01-20T09:54:27.392855Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::89
2023-01-20T09:54:27.392863Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.392872Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.392881Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.393944Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.393978Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 90
2023-01-20T09:54:27.394008Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::90
2023-01-20T09:54:27.394015Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.394024Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.394032Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.395063Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.395097Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 91
2023-01-20T09:54:27.395127Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::91
2023-01-20T09:54:27.395135Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.395144Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.395152Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.396232Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.396268Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 92
2023-01-20T09:54:27.396297Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::92
2023-01-20T09:54:27.396305Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.396315Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.396322Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.397419Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.397455Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 93
2023-01-20T09:54:27.397484Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::93
2023-01-20T09:54:27.397492Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.397501Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.397509Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.398542Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.398577Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 94
2023-01-20T09:54:27.398606Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::94
2023-01-20T09:54:27.398614Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.398623Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.398631Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.399718Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.399754Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 95
2023-01-20T09:54:27.399784Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::95
2023-01-20T09:54:27.399792Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.399801Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.399809Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.400841Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.400875Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 96
2023-01-20T09:54:27.400905Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::96
2023-01-20T09:54:27.400913Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.400922Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.400930Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.401965Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.401999Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 97
2023-01-20T09:54:27.402030Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::97
2023-01-20T09:54:27.402038Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.402047Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.402055Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.403089Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.403123Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 98
2023-01-20T09:54:27.403153Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::98
2023-01-20T09:54:27.403160Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.403169Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.403177Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.404205Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.404240Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 99
2023-01-20T09:54:27.404269Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::99
2023-01-20T09:54:27.404277Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.404286Z  INFO evm_eth_compliance::statetest::runner: TX len : 77
2023-01-20T09:54:27.404295Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.405324Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2916917,
    events_root: None,
}
2023-01-20T09:54:27.405358Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 100
2023-01-20T09:54:27.405387Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::100
2023-01-20T09:54:27.405395Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.405404Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.405412Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.406443Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.406477Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 101
2023-01-20T09:54:27.406507Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::101
2023-01-20T09:54:27.406515Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.406524Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.406531Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.407557Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.407591Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 102
2023-01-20T09:54:27.407621Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::102
2023-01-20T09:54:27.407629Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.407638Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.407645Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.408749Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.408781Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 103
2023-01-20T09:54:27.408818Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::103
2023-01-20T09:54:27.408828Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.408834Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.408840Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.410066Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.410105Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 104
2023-01-20T09:54:27.410147Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::104
2023-01-20T09:54:27.410157Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.410169Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.410178Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.411237Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.411272Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 105
2023-01-20T09:54:27.411301Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::105
2023-01-20T09:54:27.411309Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.411318Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.411326Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.412360Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.412394Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 106
2023-01-20T09:54:27.412425Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::106
2023-01-20T09:54:27.412433Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.412442Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.412451Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.413494Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.413529Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 107
2023-01-20T09:54:27.413558Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::107
2023-01-20T09:54:27.413566Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.413575Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.413583Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.414616Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.414650Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 108
2023-01-20T09:54:27.414679Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::108
2023-01-20T09:54:27.414687Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.414696Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.414703Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.415752Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.415786Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 109
2023-01-20T09:54:27.415815Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::109
2023-01-20T09:54:27.415823Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.415832Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.415840Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.416868Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.416903Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 110
2023-01-20T09:54:27.416932Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::110
2023-01-20T09:54:27.416941Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.416957Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.416964Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.417996Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.418030Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 111
2023-01-20T09:54:27.418060Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::111
2023-01-20T09:54:27.418068Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.418077Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.418084Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.419116Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.419150Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 112
2023-01-20T09:54:27.419179Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::112
2023-01-20T09:54:27.419187Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.419196Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-20T09:54:27.419204Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.420230Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2912721,
    events_root: None,
}
2023-01-20T09:54:27.420264Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 113
2023-01-20T09:54:27.420295Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::113
2023-01-20T09:54:27.420303Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.420312Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T09:54:27.420319Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.421352Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2912404,
    events_root: None,
}
2023-01-20T09:54:27.421386Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 114
2023-01-20T09:54:27.421416Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::114
2023-01-20T09:54:27.421424Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.421433Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T09:54:27.421440Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.422497Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2912404,
    events_root: None,
}
2023-01-20T09:54:27.422531Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 115
2023-01-20T09:54:27.422562Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::115
2023-01-20T09:54:27.422570Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.422579Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T09:54:27.422587Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.423618Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2912404,
    events_root: None,
}
2023-01-20T09:54:27.423653Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 116
2023-01-20T09:54:27.423682Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::116
2023-01-20T09:54:27.423690Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.423699Z  INFO evm_eth_compliance::statetest::runner: TX len : 33
2023-01-20T09:54:27.423706Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.424740Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2912771,
    events_root: None,
}
2023-01-20T09:54:27.424775Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 117
2023-01-20T09:54:27.424804Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::117
2023-01-20T09:54:27.424813Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.424822Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T09:54:27.424829Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.425866Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2913113,
    events_root: None,
}
2023-01-20T09:54:27.425900Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 118
2023-01-20T09:54:27.425931Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::118
2023-01-20T09:54:27.425939Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.425948Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T09:54:27.425955Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.427000Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2913113,
    events_root: None,
}
2023-01-20T09:54:27.427035Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 119
2023-01-20T09:54:27.427063Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::119
2023-01-20T09:54:27.427072Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.427081Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T09:54:27.427089Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.428118Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2913113,
    events_root: None,
}
2023-01-20T09:54:27.428153Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 120
2023-01-20T09:54:27.428187Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::120
2023-01-20T09:54:27.428196Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.428206Z  INFO evm_eth_compliance::statetest::runner: TX len : 34
2023-01-20T09:54:27.428214Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.429273Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2912785,
    events_root: None,
}
2023-01-20T09:54:27.429308Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 121
2023-01-20T09:54:27.429337Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::121
2023-01-20T09:54:27.429345Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.429354Z  INFO evm_eth_compliance::statetest::runner: TX len : 35
2023-01-20T09:54:27.429362Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.430491Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909166,
    events_root: None,
}
2023-01-20T09:54:27.430528Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 122
2023-01-20T09:54:27.430557Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::122
2023-01-20T09:54:27.430565Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.430572Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-20T09:54:27.430578Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.431752Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909179,
    events_root: None,
}
2023-01-20T09:54:27.431792Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 123
2023-01-20T09:54:27.431829Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::123
2023-01-20T09:54:27.431838Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.431847Z  INFO evm_eth_compliance::statetest::runner: TX len : 38
2023-01-20T09:54:27.431854Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.432918Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909205,
    events_root: None,
}
2023-01-20T09:54:27.432958Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 124
2023-01-20T09:54:27.432989Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::124
2023-01-20T09:54:27.432998Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.433007Z  INFO evm_eth_compliance::statetest::runner: TX len : 39
2023-01-20T09:54:27.433015Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.434045Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909219,
    events_root: None,
}
2023-01-20T09:54:27.434079Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 125
2023-01-20T09:54:27.434109Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::125
2023-01-20T09:54:27.434117Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.434126Z  INFO evm_eth_compliance::statetest::runner: TX len : 40
2023-01-20T09:54:27.434133Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.435173Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909232,
    events_root: None,
}
2023-01-20T09:54:27.435208Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 126
2023-01-20T09:54:27.435238Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::126
2023-01-20T09:54:27.435246Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.435255Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.435263Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.436299Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.436333Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 127
2023-01-20T09:54:27.436362Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::127
2023-01-20T09:54:27.436370Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.436379Z  INFO evm_eth_compliance::statetest::runner: TX len : 42
2023-01-20T09:54:27.436387Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.437429Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909258,
    events_root: None,
}
2023-01-20T09:54:27.437463Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 128
2023-01-20T09:54:27.437492Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::128
2023-01-20T09:54:27.437500Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.437510Z  INFO evm_eth_compliance::statetest::runner: TX len : 45
2023-01-20T09:54:27.437518Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.438555Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908782,
    events_root: None,
}
2023-01-20T09:54:27.438589Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 129
2023-01-20T09:54:27.438622Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::129
2023-01-20T09:54:27.438632Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.438641Z  INFO evm_eth_compliance::statetest::runner: TX len : 50
2023-01-20T09:54:27.438648Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.439702Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908848,
    events_root: None,
}
2023-01-20T09:54:27.439736Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 130
2023-01-20T09:54:27.439766Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::130
2023-01-20T09:54:27.439774Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.439783Z  INFO evm_eth_compliance::statetest::runner: TX len : 50
2023-01-20T09:54:27.439790Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.440826Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908848,
    events_root: None,
}
2023-01-20T09:54:27.440861Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 131
2023-01-20T09:54:27.440890Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::131
2023-01-20T09:54:27.440898Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.440907Z  INFO evm_eth_compliance::statetest::runner: TX len : 48
2023-01-20T09:54:27.440915Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.441951Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908821,
    events_root: None,
}
2023-01-20T09:54:27.441986Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 132
2023-01-20T09:54:27.442015Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::132
2023-01-20T09:54:27.442024Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.442032Z  INFO evm_eth_compliance::statetest::runner: TX len : 46
2023-01-20T09:54:27.442040Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.443078Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908795,
    events_root: None,
}
2023-01-20T09:54:27.443113Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 133
2023-01-20T09:54:27.443145Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::133
2023-01-20T09:54:27.443153Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.443162Z  INFO evm_eth_compliance::statetest::runner: TX len : 44
2023-01-20T09:54:27.443169Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.444218Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908769,
    events_root: None,
}
2023-01-20T09:54:27.444253Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 134
2023-01-20T09:54:27.444283Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::134
2023-01-20T09:54:27.444291Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.444300Z  INFO evm_eth_compliance::statetest::runner: TX len : 47
2023-01-20T09:54:27.444307Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.445364Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908808,
    events_root: None,
}
2023-01-20T09:54:27.445399Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 135
2023-01-20T09:54:27.445429Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::135
2023-01-20T09:54:27.445436Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.445445Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T09:54:27.445453Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.446483Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2913113,
    events_root: None,
}
2023-01-20T09:54:27.446517Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 136
2023-01-20T09:54:27.446547Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::136
2023-01-20T09:54:27.446554Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.446564Z  INFO evm_eth_compliance::statetest::runner: TX len : 58
2023-01-20T09:54:27.446571Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.447780Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2913205,
    events_root: None,
}
2023-01-20T09:54:27.447820Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 137
2023-01-20T09:54:27.447858Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::137
2023-01-20T09:54:27.447870Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.447879Z  INFO evm_eth_compliance::statetest::runner: TX len : 50
2023-01-20T09:54:27.447887Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.448971Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908848,
    events_root: None,
}
2023-01-20T09:54:27.449015Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 138
2023-01-20T09:54:27.449051Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::138
2023-01-20T09:54:27.449063Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.449075Z  INFO evm_eth_compliance::statetest::runner: TX len : 50
2023-01-20T09:54:27.449084Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.450129Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908848,
    events_root: None,
}
2023-01-20T09:54:27.450160Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 139
2023-01-20T09:54:27.450188Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::139
2023-01-20T09:54:27.450195Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.450202Z  INFO evm_eth_compliance::statetest::runner: TX len : 44
2023-01-20T09:54:27.450208Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.451226Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908769,
    events_root: None,
}
2023-01-20T09:54:27.451258Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 140
2023-01-20T09:54:27.451286Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::140
2023-01-20T09:54:27.451293Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.451300Z  INFO evm_eth_compliance::statetest::runner: TX len : 52
2023-01-20T09:54:27.451306Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.452315Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2913126,
    events_root: None,
}
2023-01-20T09:54:27.452346Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 141
2023-01-20T09:54:27.452373Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::141
2023-01-20T09:54:27.452381Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.452388Z  INFO evm_eth_compliance::statetest::runner: TX len : 53
2023-01-20T09:54:27.452394Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.453413Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2913139,
    events_root: None,
}
2023-01-20T09:54:27.453444Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 142
2023-01-20T09:54:27.453472Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::142
2023-01-20T09:54:27.453479Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.453486Z  INFO evm_eth_compliance::statetest::runner: TX len : 53
2023-01-20T09:54:27.453492Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.454510Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2913139,
    events_root: None,
}
2023-01-20T09:54:27.454543Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 143
2023-01-20T09:54:27.454571Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::143
2023-01-20T09:54:27.454578Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.454585Z  INFO evm_eth_compliance::statetest::runner: TX len : 53
2023-01-20T09:54:27.454591Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.455607Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2913139,
    events_root: None,
}
2023-01-20T09:54:27.455637Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 144
2023-01-20T09:54:27.455665Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::144
2023-01-20T09:54:27.455672Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.455679Z  INFO evm_eth_compliance::statetest::runner: TX len : 47
2023-01-20T09:54:27.455685Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.456704Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908808,
    events_root: None,
}
2023-01-20T09:54:27.456735Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 145
2023-01-20T09:54:27.456763Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::145
2023-01-20T09:54:27.456770Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.456778Z  INFO evm_eth_compliance::statetest::runner: TX len : 48
2023-01-20T09:54:27.456784Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.457806Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908821,
    events_root: None,
}
2023-01-20T09:54:27.457836Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 146
2023-01-20T09:54:27.457864Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::146
2023-01-20T09:54:27.457871Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.457878Z  INFO evm_eth_compliance::statetest::runner: TX len : 43
2023-01-20T09:54:27.457884Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.458903Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908755,
    events_root: None,
}
2023-01-20T09:54:27.458934Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 147
2023-01-20T09:54:27.458961Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::147
2023-01-20T09:54:27.458968Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.458975Z  INFO evm_eth_compliance::statetest::runner: TX len : 44
2023-01-20T09:54:27.458981Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.460019Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908769,
    events_root: None,
}
2023-01-20T09:54:27.460049Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 148
2023-01-20T09:54:27.460079Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::148
2023-01-20T09:54:27.460086Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.460093Z  INFO evm_eth_compliance::statetest::runner: TX len : 45
2023-01-20T09:54:27.460100Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.461122Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2908782,
    events_root: None,
}
2023-01-20T09:54:27.461152Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 149
2023-01-20T09:54:27.461181Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::149
2023-01-20T09:54:27.461188Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.461195Z  INFO evm_eth_compliance::statetest::runner: TX len : 52
2023-01-20T09:54:27.461200Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.462206Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2913126,
    events_root: None,
}
2023-01-20T09:54:27.462236Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 150
2023-01-20T09:54:27.462264Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::150
2023-01-20T09:54:27.462270Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.462277Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T09:54:27.462283Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.463284Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2913113,
    events_root: None,
}
2023-01-20T09:54:27.463315Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 151
2023-01-20T09:54:27.463344Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::151
2023-01-20T09:54:27.463351Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.463358Z  INFO evm_eth_compliance::statetest::runner: TX len : 54
2023-01-20T09:54:27.463364Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.464392Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2913153,
    events_root: None,
}
2023-01-20T09:54:27.464423Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 152
2023-01-20T09:54:27.464460Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::152
2023-01-20T09:54:27.464471Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.464482Z  INFO evm_eth_compliance::statetest::runner: TX len : 56
2023-01-20T09:54:27.464491Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.465716Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2913179,
    events_root: None,
}
2023-01-20T09:54:27.465764Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 153
2023-01-20T09:54:27.465809Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::153
2023-01-20T09:54:27.465819Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.465826Z  INFO evm_eth_compliance::statetest::runner: TX len : 58
2023-01-20T09:54:27.465832Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.466880Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2913205,
    events_root: None,
}
2023-01-20T09:54:27.466910Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 154
2023-01-20T09:54:27.466941Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::154
2023-01-20T09:54:27.466948Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.466955Z  INFO evm_eth_compliance::statetest::runner: TX len : 65
2023-01-20T09:54:27.466961Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.467969Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2912483,
    events_root: None,
}
2023-01-20T09:54:27.467999Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 155
2023-01-20T09:54:27.468026Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::155
2023-01-20T09:54:27.468033Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.468040Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.468046Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.469091Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.469122Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 156
2023-01-20T09:54:27.469150Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::156
2023-01-20T09:54:27.469157Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.469164Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.469170Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.470192Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.470222Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 157
2023-01-20T09:54:27.470250Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::157
2023-01-20T09:54:27.470256Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.470263Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.470269Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.471282Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.471312Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 158
2023-01-20T09:54:27.471340Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::158
2023-01-20T09:54:27.471347Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.471354Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T09:54:27.471360Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.472367Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2913113,
    events_root: None,
}
2023-01-20T09:54:27.472397Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 159
2023-01-20T09:54:27.472425Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::159
2023-01-20T09:54:27.472432Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.472439Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T09:54:27.472445Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.473467Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2913113,
    events_root: None,
}
2023-01-20T09:54:27.473497Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 160
2023-01-20T09:54:27.473525Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::160
2023-01-20T09:54:27.473532Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.473539Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T09:54:27.473545Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.474556Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2913113,
    events_root: None,
}
2023-01-20T09:54:27.474587Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 161
2023-01-20T09:54:27.474614Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::161
2023-01-20T09:54:27.474621Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.474628Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T09:54:27.474634Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.475645Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2913113,
    events_root: None,
}
2023-01-20T09:54:27.475676Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 162
2023-01-20T09:54:27.475703Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::162
2023-01-20T09:54:27.475710Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.475717Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T09:54:27.475725Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.476735Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2913113,
    events_root: None,
}
2023-01-20T09:54:27.476765Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 163
2023-01-20T09:54:27.476794Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::163
2023-01-20T09:54:27.476801Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.476807Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T09:54:27.476813Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.477831Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2913113,
    events_root: None,
}
2023-01-20T09:54:27.477861Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 164
2023-01-20T09:54:27.477888Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::164
2023-01-20T09:54:27.477895Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.477902Z  INFO evm_eth_compliance::statetest::runner: TX len : 55
2023-01-20T09:54:27.477908Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.478929Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2913166,
    events_root: None,
}
2023-01-20T09:54:27.478959Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 165
2023-01-20T09:54:27.478989Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::165
2023-01-20T09:54:27.478996Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.479003Z  INFO evm_eth_compliance::statetest::runner: TX len : 55
2023-01-20T09:54:27.479009Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.480021Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2913166,
    events_root: None,
}
2023-01-20T09:54:27.480051Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 166
2023-01-20T09:54:27.480079Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::166
2023-01-20T09:54:27.480086Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.480093Z  INFO evm_eth_compliance::statetest::runner: TX len : 55
2023-01-20T09:54:27.480099Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.481123Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2913166,
    events_root: None,
}
2023-01-20T09:54:27.481153Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 167
2023-01-20T09:54:27.481181Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::167
2023-01-20T09:54:27.481189Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.481196Z  INFO evm_eth_compliance::statetest::runner: TX len : 24
2023-01-20T09:54:27.481202Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.482216Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909500,
    events_root: None,
}
2023-01-20T09:54:27.482248Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 168
2023-01-20T09:54:27.482277Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Merge::168
2023-01-20T09:54:27.482283Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.482290Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-20T09:54:27.482296Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.483309Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2912721,
    events_root: None,
}
2023-01-20T09:54:27.483342Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 0
2023-01-20T09:54:27.483371Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::0
2023-01-20T09:54:27.483378Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.483385Z  INFO evm_eth_compliance::statetest::runner: TX len : 1
2023-01-20T09:54:27.483391Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.484418Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910289,
    events_root: None,
}
2023-01-20T09:54:27.484449Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 1
2023-01-20T09:54:27.484478Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::1
2023-01-20T09:54:27.484485Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.484492Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T09:54:27.484498Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.485628Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2912404,
    events_root: None,
}
2023-01-20T09:54:27.485676Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 2
2023-01-20T09:54:27.485723Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::2
2023-01-20T09:54:27.485732Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.485739Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T09:54:27.485746Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.487070Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2912404,
    events_root: None,
}
2023-01-20T09:54:27.487118Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 3
2023-01-20T09:54:27.487169Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::3
2023-01-20T09:54:27.487177Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.487184Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T09:54:27.487190Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.488337Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2912404,
    events_root: None,
}
2023-01-20T09:54:27.488369Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 4
2023-01-20T09:54:27.488398Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::4
2023-01-20T09:54:27.488404Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.488411Z  INFO evm_eth_compliance::statetest::runner: TX len : 2
2023-01-20T09:54:27.488417Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.489433Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910303,
    events_root: None,
}
2023-01-20T09:54:27.489463Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 5
2023-01-20T09:54:27.489491Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::5
2023-01-20T09:54:27.489498Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.489505Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T09:54:27.489511Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.490520Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2912404,
    events_root: None,
}
2023-01-20T09:54:27.490550Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 6
2023-01-20T09:54:27.490578Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::6
2023-01-20T09:54:27.490585Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.490592Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T09:54:27.490598Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.491628Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2912404,
    events_root: None,
}
2023-01-20T09:54:27.491659Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 7
2023-01-20T09:54:27.491688Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::7
2023-01-20T09:54:27.491695Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.491702Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T09:54:27.491708Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.492726Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2912404,
    events_root: None,
}
2023-01-20T09:54:27.492756Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 8
2023-01-20T09:54:27.492785Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::8
2023-01-20T09:54:27.492792Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.492802Z  INFO evm_eth_compliance::statetest::runner: TX len : 3
2023-01-20T09:54:27.492811Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.493851Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910316,
    events_root: None,
}
2023-01-20T09:54:27.493883Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 9
2023-01-20T09:54:27.493911Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::9
2023-01-20T09:54:27.493918Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.493926Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T09:54:27.493932Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.494979Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910329,
    events_root: None,
}
2023-01-20T09:54:27.495011Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 10
2023-01-20T09:54:27.495042Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::10
2023-01-20T09:54:27.495049Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.495056Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-20T09:54:27.495062Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.496097Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910329,
    events_root: None,
}
2023-01-20T09:54:27.496128Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 11
2023-01-20T09:54:27.496156Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::11
2023-01-20T09:54:27.496163Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.496170Z  INFO evm_eth_compliance::statetest::runner: TX len : 5
2023-01-20T09:54:27.496176Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.497211Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910354,
    events_root: None,
}
2023-01-20T09:54:27.497245Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 12
2023-01-20T09:54:27.497274Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::12
2023-01-20T09:54:27.497281Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.497288Z  INFO evm_eth_compliance::statetest::runner: TX len : 7
2023-01-20T09:54:27.497294Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.498327Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910381,
    events_root: None,
}
2023-01-20T09:54:27.498358Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 13
2023-01-20T09:54:27.498387Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::13
2023-01-20T09:54:27.498394Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.498401Z  INFO evm_eth_compliance::statetest::runner: TX len : 8
2023-01-20T09:54:27.498407Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.499440Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910394,
    events_root: None,
}
2023-01-20T09:54:27.499472Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 14
2023-01-20T09:54:27.499502Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::14
2023-01-20T09:54:27.499509Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.499516Z  INFO evm_eth_compliance::statetest::runner: TX len : 9
2023-01-20T09:54:27.499522Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.500550Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910407,
    events_root: None,
}
2023-01-20T09:54:27.500583Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 15
2023-01-20T09:54:27.500612Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::15
2023-01-20T09:54:27.500619Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.500626Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T09:54:27.500631Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.501748Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910420,
    events_root: None,
}
2023-01-20T09:54:27.501781Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 16
2023-01-20T09:54:27.501812Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::16
2023-01-20T09:54:27.501820Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.501827Z  INFO evm_eth_compliance::statetest::runner: TX len : 11
2023-01-20T09:54:27.501833Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.502968Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910433,
    events_root: None,
}
2023-01-20T09:54:27.503006Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 17
2023-01-20T09:54:27.503045Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::17
2023-01-20T09:54:27.503052Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.503059Z  INFO evm_eth_compliance::statetest::runner: TX len : 14
2023-01-20T09:54:27.503065Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.504152Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909897,
    events_root: None,
}
2023-01-20T09:54:27.504185Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 18
2023-01-20T09:54:27.504216Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::18
2023-01-20T09:54:27.504224Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.504231Z  INFO evm_eth_compliance::statetest::runner: TX len : 19
2023-01-20T09:54:27.504237Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.505275Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909963,
    events_root: None,
}
2023-01-20T09:54:27.505305Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 19
2023-01-20T09:54:27.505333Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::19
2023-01-20T09:54:27.505341Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.505348Z  INFO evm_eth_compliance::statetest::runner: TX len : 19
2023-01-20T09:54:27.505353Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.506361Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909963,
    events_root: None,
}
2023-01-20T09:54:27.506393Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 20
2023-01-20T09:54:27.506420Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::20
2023-01-20T09:54:27.506427Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.506435Z  INFO evm_eth_compliance::statetest::runner: TX len : 17
2023-01-20T09:54:27.506441Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.507466Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909937,
    events_root: None,
}
2023-01-20T09:54:27.507497Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 21
2023-01-20T09:54:27.507525Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::21
2023-01-20T09:54:27.507533Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.507540Z  INFO evm_eth_compliance::statetest::runner: TX len : 15
2023-01-20T09:54:27.507545Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.508567Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909910,
    events_root: None,
}
2023-01-20T09:54:27.508598Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 22
2023-01-20T09:54:27.508625Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::22
2023-01-20T09:54:27.508633Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.508640Z  INFO evm_eth_compliance::statetest::runner: TX len : 13
2023-01-20T09:54:27.508646Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.509662Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909884,
    events_root: None,
}
2023-01-20T09:54:27.509693Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 23
2023-01-20T09:54:27.509720Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::23
2023-01-20T09:54:27.509727Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.509735Z  INFO evm_eth_compliance::statetest::runner: TX len : 19
2023-01-20T09:54:27.509740Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.510749Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909963,
    events_root: None,
}
2023-01-20T09:54:27.510780Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 24
2023-01-20T09:54:27.510807Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::24
2023-01-20T09:54:27.510814Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.510821Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T09:54:27.510827Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.511839Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909240,
    events_root: None,
}
2023-01-20T09:54:27.511870Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 25
2023-01-20T09:54:27.511897Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::25
2023-01-20T09:54:27.511904Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.511911Z  INFO evm_eth_compliance::statetest::runner: TX len : 27
2023-01-20T09:54:27.511917Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.512923Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2914863,
    events_root: None,
}
2023-01-20T09:54:27.512958Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 26
2023-01-20T09:54:27.512986Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::26
2023-01-20T09:54:27.512993Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.513000Z  INFO evm_eth_compliance::statetest::runner: TX len : 19
2023-01-20T09:54:27.513006Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.514012Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909963,
    events_root: None,
}
2023-01-20T09:54:27.514042Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 27
2023-01-20T09:54:27.514070Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::27
2023-01-20T09:54:27.514077Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.514084Z  INFO evm_eth_compliance::statetest::runner: TX len : 19
2023-01-20T09:54:27.514090Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.515095Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909963,
    events_root: None,
}
2023-01-20T09:54:27.515126Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 28
2023-01-20T09:54:27.515153Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::28
2023-01-20T09:54:27.515161Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.515168Z  INFO evm_eth_compliance::statetest::runner: TX len : 13
2023-01-20T09:54:27.515174Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.516180Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909884,
    events_root: None,
}
2023-01-20T09:54:27.516213Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 29
2023-01-20T09:54:27.516243Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::29
2023-01-20T09:54:27.516250Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.516257Z  INFO evm_eth_compliance::statetest::runner: TX len : 21
2023-01-20T09:54:27.516264Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.517272Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909253,
    events_root: None,
}
2023-01-20T09:54:27.517303Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 30
2023-01-20T09:54:27.517330Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::30
2023-01-20T09:54:27.517337Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.517344Z  INFO evm_eth_compliance::statetest::runner: TX len : 22
2023-01-20T09:54:27.517350Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.518356Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909267,
    events_root: None,
}
2023-01-20T09:54:27.518386Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 31
2023-01-20T09:54:27.518414Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::31
2023-01-20T09:54:27.518421Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.518428Z  INFO evm_eth_compliance::statetest::runner: TX len : 22
2023-01-20T09:54:27.518434Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.519447Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909267,
    events_root: None,
}
2023-01-20T09:54:27.519477Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 32
2023-01-20T09:54:27.519506Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::32
2023-01-20T09:54:27.519513Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.519520Z  INFO evm_eth_compliance::statetest::runner: TX len : 22
2023-01-20T09:54:27.519526Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.520528Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909267,
    events_root: None,
}
2023-01-20T09:54:27.520559Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 33
2023-01-20T09:54:27.520586Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::33
2023-01-20T09:54:27.520594Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.520601Z  INFO evm_eth_compliance::statetest::runner: TX len : 16
2023-01-20T09:54:27.520607Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.521627Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909923,
    events_root: None,
}
2023-01-20T09:54:27.521659Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 34
2023-01-20T09:54:27.521689Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::34
2023-01-20T09:54:27.521697Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.521704Z  INFO evm_eth_compliance::statetest::runner: TX len : 17
2023-01-20T09:54:27.521710Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.522807Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909937,
    events_root: None,
}
2023-01-20T09:54:27.522850Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 35
2023-01-20T09:54:27.522893Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::35
2023-01-20T09:54:27.522900Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.522907Z  INFO evm_eth_compliance::statetest::runner: TX len : 12
2023-01-20T09:54:27.522914Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.523979Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909859,
    events_root: None,
}
2023-01-20T09:54:27.524009Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 36
2023-01-20T09:54:27.524038Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::36
2023-01-20T09:54:27.524045Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.524052Z  INFO evm_eth_compliance::statetest::runner: TX len : 13
2023-01-20T09:54:27.524058Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.525077Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909884,
    events_root: None,
}
2023-01-20T09:54:27.525108Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 37
2023-01-20T09:54:27.525136Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::37
2023-01-20T09:54:27.525143Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.525150Z  INFO evm_eth_compliance::statetest::runner: TX len : 14
2023-01-20T09:54:27.525156Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.526274Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909897,
    events_root: None,
}
2023-01-20T09:54:27.526304Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 38
2023-01-20T09:54:27.526332Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::38
2023-01-20T09:54:27.526338Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.526345Z  INFO evm_eth_compliance::statetest::runner: TX len : 21
2023-01-20T09:54:27.526351Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.527356Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909253,
    events_root: None,
}
2023-01-20T09:54:27.527387Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 39
2023-01-20T09:54:27.527415Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::39
2023-01-20T09:54:27.527422Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.527429Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T09:54:27.527435Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.528443Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909240,
    events_root: None,
}
2023-01-20T09:54:27.528474Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 40
2023-01-20T09:54:27.528501Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::40
2023-01-20T09:54:27.528508Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.528515Z  INFO evm_eth_compliance::statetest::runner: TX len : 23
2023-01-20T09:54:27.528521Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.529555Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909280,
    events_root: None,
}
2023-01-20T09:54:27.529586Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 41
2023-01-20T09:54:27.529614Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::41
2023-01-20T09:54:27.529621Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.529628Z  INFO evm_eth_compliance::statetest::runner: TX len : 25
2023-01-20T09:54:27.529634Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.530640Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909513,
    events_root: None,
}
2023-01-20T09:54:27.530671Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 42
2023-01-20T09:54:27.530699Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::42
2023-01-20T09:54:27.530706Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.530713Z  INFO evm_eth_compliance::statetest::runner: TX len : 27
2023-01-20T09:54:27.530719Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.531722Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2914863,
    events_root: None,
}
2023-01-20T09:54:27.531752Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 43
2023-01-20T09:54:27.531780Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::43
2023-01-20T09:54:27.531787Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.531794Z  INFO evm_eth_compliance::statetest::runner: TX len : 34
2023-01-20T09:54:27.531800Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.532811Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2912785,
    events_root: None,
}
2023-01-20T09:54:27.532841Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 44
2023-01-20T09:54:27.532869Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::44
2023-01-20T09:54:27.532876Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.532883Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T09:54:27.532889Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.533908Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910420,
    events_root: None,
}
2023-01-20T09:54:27.533939Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 45
2023-01-20T09:54:27.533970Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::45
2023-01-20T09:54:27.533977Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.533984Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T09:54:27.533990Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.535008Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910420,
    events_root: None,
}
2023-01-20T09:54:27.535039Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 46
2023-01-20T09:54:27.535067Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::46
2023-01-20T09:54:27.535074Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.535081Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T09:54:27.535087Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.536100Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910420,
    events_root: None,
}
2023-01-20T09:54:27.536130Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 47
2023-01-20T09:54:27.536157Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::47
2023-01-20T09:54:27.536164Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.536171Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T09:54:27.536177Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.537192Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909240,
    events_root: None,
}
2023-01-20T09:54:27.537222Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 48
2023-01-20T09:54:27.537250Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::48
2023-01-20T09:54:27.537258Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.537265Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T09:54:27.537271Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.538280Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909240,
    events_root: None,
}
2023-01-20T09:54:27.538312Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 49
2023-01-20T09:54:27.538350Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::49
2023-01-20T09:54:27.538361Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.538371Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T09:54:27.538380Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.539588Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909240,
    events_root: None,
}
2023-01-20T09:54:27.539628Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 50
2023-01-20T09:54:27.539668Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::50
2023-01-20T09:54:27.539675Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.539683Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T09:54:27.539689Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.540763Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909240,
    events_root: None,
}
2023-01-20T09:54:27.540794Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 51
2023-01-20T09:54:27.540823Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::51
2023-01-20T09:54:27.540830Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.540837Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T09:54:27.540842Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.541858Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909240,
    events_root: None,
}
2023-01-20T09:54:27.541888Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 52
2023-01-20T09:54:27.541917Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::52
2023-01-20T09:54:27.541923Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.541930Z  INFO evm_eth_compliance::statetest::runner: TX len : 20
2023-01-20T09:54:27.541936Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.542945Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909240,
    events_root: None,
}
2023-01-20T09:54:27.542975Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 53
2023-01-20T09:54:27.543003Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::53
2023-01-20T09:54:27.543010Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.543017Z  INFO evm_eth_compliance::statetest::runner: TX len : 24
2023-01-20T09:54:27.543023Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.544028Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909500,
    events_root: None,
}
2023-01-20T09:54:27.544059Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 54
2023-01-20T09:54:27.544086Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::54
2023-01-20T09:54:27.544094Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.544101Z  INFO evm_eth_compliance::statetest::runner: TX len : 24
2023-01-20T09:54:27.544107Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.545127Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909500,
    events_root: None,
}
2023-01-20T09:54:27.545158Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 55
2023-01-20T09:54:27.545185Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::55
2023-01-20T09:54:27.545193Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.545200Z  INFO evm_eth_compliance::statetest::runner: TX len : 24
2023-01-20T09:54:27.545206Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.546214Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909500,
    events_root: None,
}
2023-01-20T09:54:27.546244Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 56
2023-01-20T09:54:27.546274Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::56
2023-01-20T09:54:27.546283Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.546291Z  INFO evm_eth_compliance::statetest::runner: TX len : 10
2023-01-20T09:54:27.546297Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.547303Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910420,
    events_root: None,
}
2023-01-20T09:54:27.547334Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 57
2023-01-20T09:54:27.547362Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::57
2023-01-20T09:54:27.547368Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.547375Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.547381Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.548386Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.548417Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 58
2023-01-20T09:54:27.548445Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::58
2023-01-20T09:54:27.548451Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.548458Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.548464Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.549478Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.549508Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 59
2023-01-20T09:54:27.549537Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::59
2023-01-20T09:54:27.549544Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.549551Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.549556Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.550562Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.550592Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 60
2023-01-20T09:54:27.550620Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::60
2023-01-20T09:54:27.550628Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.550635Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.550641Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.551646Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.551677Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 61
2023-01-20T09:54:27.551704Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::61
2023-01-20T09:54:27.551711Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.551718Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.551725Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.552736Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.552767Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 62
2023-01-20T09:54:27.552794Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::62
2023-01-20T09:54:27.552801Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.552808Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.552814Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.553829Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.553861Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 63
2023-01-20T09:54:27.553888Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::63
2023-01-20T09:54:27.553895Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.553902Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.553908Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.554916Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.554947Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 64
2023-01-20T09:54:27.554975Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::64
2023-01-20T09:54:27.554981Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.554988Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.554994Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.556005Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.556036Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 65
2023-01-20T09:54:27.556064Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::65
2023-01-20T09:54:27.556071Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.556078Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.556084Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.557094Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.557124Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 66
2023-01-20T09:54:27.557152Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::66
2023-01-20T09:54:27.557161Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.557168Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.557173Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.558277Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.558323Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 67
2023-01-20T09:54:27.558365Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::67
2023-01-20T09:54:27.558374Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.558381Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.558388Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.559549Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.559582Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 68
2023-01-20T09:54:27.559615Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::68
2023-01-20T09:54:27.559622Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.559629Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.559635Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.560651Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.560680Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 69
2023-01-20T09:54:27.560709Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::69
2023-01-20T09:54:27.560716Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.560723Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.560729Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.561752Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.561783Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 70
2023-01-20T09:54:27.561811Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::70
2023-01-20T09:54:27.561818Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.561825Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.561831Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.562838Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.562868Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 71
2023-01-20T09:54:27.562896Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::71
2023-01-20T09:54:27.562903Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.562910Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.562916Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.563921Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.563952Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 72
2023-01-20T09:54:27.563979Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::72
2023-01-20T09:54:27.563986Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.563994Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.564000Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.565016Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.565047Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 73
2023-01-20T09:54:27.565075Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::73
2023-01-20T09:54:27.565082Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.565090Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.565096Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.566102Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.566133Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 74
2023-01-20T09:54:27.566160Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::74
2023-01-20T09:54:27.566167Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.566174Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.566180Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.567185Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.567215Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 75
2023-01-20T09:54:27.567243Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::75
2023-01-20T09:54:27.567250Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.567257Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.567263Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.568275Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.568305Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 76
2023-01-20T09:54:27.568334Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::76
2023-01-20T09:54:27.568340Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.568347Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.568353Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.569377Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.569407Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 77
2023-01-20T09:54:27.569437Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::77
2023-01-20T09:54:27.569443Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.569450Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.569456Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.570507Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.570538Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 78
2023-01-20T09:54:27.570566Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::78
2023-01-20T09:54:27.570573Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.570580Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.570587Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.571601Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.571631Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 79
2023-01-20T09:54:27.571660Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::79
2023-01-20T09:54:27.571666Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.571673Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.571680Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.572689Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.572720Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 80
2023-01-20T09:54:27.572748Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::80
2023-01-20T09:54:27.572755Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.572762Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.572768Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.573858Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.573891Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 81
2023-01-20T09:54:27.573921Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::81
2023-01-20T09:54:27.573928Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.573935Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.573942Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.575154Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.575198Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 82
2023-01-20T09:54:27.575238Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::82
2023-01-20T09:54:27.575245Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.575252Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.575258Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.576297Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.576331Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 83
2023-01-20T09:54:27.576361Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::83
2023-01-20T09:54:27.576368Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.576375Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.576382Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.577407Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.577438Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 84
2023-01-20T09:54:27.577466Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::84
2023-01-20T09:54:27.577473Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.577481Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.577487Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.578500Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.578530Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 85
2023-01-20T09:54:27.578558Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::85
2023-01-20T09:54:27.578565Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.578572Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.578579Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.579589Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2909245,
    events_root: None,
}
2023-01-20T09:54:27.579620Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 86
2023-01-20T09:54:27.579648Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::86
2023-01-20T09:54:27.579655Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.579662Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.579668Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.580678Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910427,
    events_root: None,
}
2023-01-20T09:54:27.580708Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 87
2023-01-20T09:54:27.580737Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::87
2023-01-20T09:54:27.580744Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.580751Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.580757Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.581795Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910607,
    events_root: None,
}
2023-01-20T09:54:27.581827Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 88
2023-01-20T09:54:27.581856Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::88
2023-01-20T09:54:27.581863Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.581870Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.581877Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.582891Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910607,
    events_root: None,
}
2023-01-20T09:54:27.582921Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 89
2023-01-20T09:54:27.582949Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::89
2023-01-20T09:54:27.582955Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.582962Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.582968Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.583977Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910607,
    events_root: None,
}
2023-01-20T09:54:27.584007Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 90
2023-01-20T09:54:27.584035Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::90
2023-01-20T09:54:27.584042Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.584049Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.584055Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.585071Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910607,
    events_root: None,
}
2023-01-20T09:54:27.585101Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 91
2023-01-20T09:54:27.585129Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::91
2023-01-20T09:54:27.585136Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.585143Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.585148Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.586162Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910607,
    events_root: None,
}
2023-01-20T09:54:27.586192Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 92
2023-01-20T09:54:27.586221Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::92
2023-01-20T09:54:27.586228Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.586235Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.586240Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.587253Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910607,
    events_root: None,
}
2023-01-20T09:54:27.587283Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 93
2023-01-20T09:54:27.587311Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::93
2023-01-20T09:54:27.587318Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.587325Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.587331Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.588336Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910607,
    events_root: None,
}
2023-01-20T09:54:27.588367Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 94
2023-01-20T09:54:27.588395Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::94
2023-01-20T09:54:27.588402Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.588409Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.588415Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.589434Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910607,
    events_root: None,
}
2023-01-20T09:54:27.589464Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 95
2023-01-20T09:54:27.589491Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::95
2023-01-20T09:54:27.589498Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.589506Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.589512Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.590519Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910607,
    events_root: None,
}
2023-01-20T09:54:27.590550Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 96
2023-01-20T09:54:27.590578Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::96
2023-01-20T09:54:27.590585Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.590591Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.590597Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.591604Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910607,
    events_root: None,
}
2023-01-20T09:54:27.591634Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 97
2023-01-20T09:54:27.591662Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::97
2023-01-20T09:54:27.591670Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.591677Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.591682Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.592686Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910607,
    events_root: None,
}
2023-01-20T09:54:27.592717Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 98
2023-01-20T09:54:27.592745Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::98
2023-01-20T09:54:27.592752Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.592759Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.592765Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.593880Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910607,
    events_root: None,
}
2023-01-20T09:54:27.593913Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 99
2023-01-20T09:54:27.593954Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::99
2023-01-20T09:54:27.593966Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.593977Z  INFO evm_eth_compliance::statetest::runner: TX len : 77
2023-01-20T09:54:27.593986Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.595138Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2918279,
    events_root: None,
}
2023-01-20T09:54:27.595172Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 100
2023-01-20T09:54:27.595206Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::100
2023-01-20T09:54:27.595213Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.595220Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.595226Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.596261Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910607,
    events_root: None,
}
2023-01-20T09:54:27.596291Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 101
2023-01-20T09:54:27.596320Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::101
2023-01-20T09:54:27.596326Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.596334Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.596340Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.597400Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910607,
    events_root: None,
}
2023-01-20T09:54:27.597432Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 102
2023-01-20T09:54:27.597460Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::102
2023-01-20T09:54:27.597467Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.597474Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.597480Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.598495Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910607,
    events_root: None,
}
2023-01-20T09:54:27.598526Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 103
2023-01-20T09:54:27.598554Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::103
2023-01-20T09:54:27.598560Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.598567Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.598573Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.599580Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910607,
    events_root: None,
}
2023-01-20T09:54:27.599610Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 104
2023-01-20T09:54:27.599638Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::104
2023-01-20T09:54:27.599645Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.599652Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.599658Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.600667Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910607,
    events_root: None,
}
2023-01-20T09:54:27.600698Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 105
2023-01-20T09:54:27.600725Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::105
2023-01-20T09:54:27.600732Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.600739Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.600745Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.601777Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910607,
    events_root: None,
}
2023-01-20T09:54:27.601807Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 106
2023-01-20T09:54:27.601835Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::106
2023-01-20T09:54:27.601842Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.601849Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.601855Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.602870Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910607,
    events_root: None,
}
2023-01-20T09:54:27.602900Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 107
2023-01-20T09:54:27.602927Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::107
2023-01-20T09:54:27.602935Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.602942Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.602948Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.603955Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910607,
    events_root: None,
}
2023-01-20T09:54:27.603986Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 108
2023-01-20T09:54:27.604014Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::108
2023-01-20T09:54:27.604020Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.604028Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.604034Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.605072Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910607,
    events_root: None,
}
2023-01-20T09:54:27.605103Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 109
2023-01-20T09:54:27.605131Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::109
2023-01-20T09:54:27.605138Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.605145Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.605151Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.606157Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910607,
    events_root: None,
}
2023-01-20T09:54:27.606187Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 110
2023-01-20T09:54:27.606215Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::110
2023-01-20T09:54:27.606222Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.606230Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.606236Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.607243Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910607,
    events_root: None,
}
2023-01-20T09:54:27.607275Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 111
2023-01-20T09:54:27.607302Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::111
2023-01-20T09:54:27.607309Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.607316Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.607321Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.608329Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910607,
    events_root: None,
}
2023-01-20T09:54:27.608359Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 112
2023-01-20T09:54:27.608390Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::112
2023-01-20T09:54:27.608398Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.608406Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-20T09:54:27.608412Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.609424Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2914083,
    events_root: None,
}
2023-01-20T09:54:27.609455Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 113
2023-01-20T09:54:27.609483Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::113
2023-01-20T09:54:27.609490Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.609497Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T09:54:27.609503Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.610505Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2913765,
    events_root: None,
}
2023-01-20T09:54:27.610536Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 114
2023-01-20T09:54:27.610564Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::114
2023-01-20T09:54:27.610574Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.610582Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T09:54:27.610588Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.611655Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2913765,
    events_root: None,
}
2023-01-20T09:54:27.611691Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 115
2023-01-20T09:54:27.611725Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::115
2023-01-20T09:54:27.611732Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.611739Z  INFO evm_eth_compliance::statetest::runner: TX len : 60
2023-01-20T09:54:27.611745Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.612906Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2913765,
    events_root: None,
}
2023-01-20T09:54:27.612940Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 116
2023-01-20T09:54:27.612981Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::116
2023-01-20T09:54:27.612989Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.612997Z  INFO evm_eth_compliance::statetest::runner: TX len : 33
2023-01-20T09:54:27.613003Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.614022Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2914133,
    events_root: None,
}
2023-01-20T09:54:27.614052Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 117
2023-01-20T09:54:27.614080Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::117
2023-01-20T09:54:27.614087Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.614094Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T09:54:27.614100Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.615107Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2914475,
    events_root: None,
}
2023-01-20T09:54:27.615138Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 118
2023-01-20T09:54:27.615165Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::118
2023-01-20T09:54:27.615172Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.615179Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T09:54:27.615185Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.616192Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2914475,
    events_root: None,
}
2023-01-20T09:54:27.616222Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 119
2023-01-20T09:54:27.616250Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::119
2023-01-20T09:54:27.616257Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.616264Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T09:54:27.616270Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.617283Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2914475,
    events_root: None,
}
2023-01-20T09:54:27.617313Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 120
2023-01-20T09:54:27.617341Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::120
2023-01-20T09:54:27.617348Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.617355Z  INFO evm_eth_compliance::statetest::runner: TX len : 34
2023-01-20T09:54:27.617361Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.618371Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2914146,
    events_root: None,
}
2023-01-20T09:54:27.618401Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 121
2023-01-20T09:54:27.618428Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::121
2023-01-20T09:54:27.618436Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.618443Z  INFO evm_eth_compliance::statetest::runner: TX len : 35
2023-01-20T09:54:27.618449Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.619459Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910527,
    events_root: None,
}
2023-01-20T09:54:27.619490Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 122
2023-01-20T09:54:27.619517Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::122
2023-01-20T09:54:27.619524Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.619532Z  INFO evm_eth_compliance::statetest::runner: TX len : 36
2023-01-20T09:54:27.619538Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.620545Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910541,
    events_root: None,
}
2023-01-20T09:54:27.620577Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 123
2023-01-20T09:54:27.620604Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::123
2023-01-20T09:54:27.620611Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.620618Z  INFO evm_eth_compliance::statetest::runner: TX len : 38
2023-01-20T09:54:27.620624Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.621650Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910567,
    events_root: None,
}
2023-01-20T09:54:27.621681Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 124
2023-01-20T09:54:27.621709Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::124
2023-01-20T09:54:27.621715Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.621722Z  INFO evm_eth_compliance::statetest::runner: TX len : 39
2023-01-20T09:54:27.621729Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.622737Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910580,
    events_root: None,
}
2023-01-20T09:54:27.622768Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 125
2023-01-20T09:54:27.622795Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::125
2023-01-20T09:54:27.622802Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.622809Z  INFO evm_eth_compliance::statetest::runner: TX len : 40
2023-01-20T09:54:27.622815Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.623821Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910593,
    events_root: None,
}
2023-01-20T09:54:27.623851Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 126
2023-01-20T09:54:27.623879Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::126
2023-01-20T09:54:27.623886Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.623893Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.623899Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.624909Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910607,
    events_root: None,
}
2023-01-20T09:54:27.624939Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 127
2023-01-20T09:54:27.624972Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::127
2023-01-20T09:54:27.624980Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.624987Z  INFO evm_eth_compliance::statetest::runner: TX len : 42
2023-01-20T09:54:27.624993Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.626001Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910620,
    events_root: None,
}
2023-01-20T09:54:27.626031Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 128
2023-01-20T09:54:27.626058Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::128
2023-01-20T09:54:27.626066Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.626073Z  INFO evm_eth_compliance::statetest::runner: TX len : 45
2023-01-20T09:54:27.626079Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.627084Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910143,
    events_root: None,
}
2023-01-20T09:54:27.627114Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 129
2023-01-20T09:54:27.627150Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::129
2023-01-20T09:54:27.627158Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.627166Z  INFO evm_eth_compliance::statetest::runner: TX len : 50
2023-01-20T09:54:27.627171Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.628181Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910209,
    events_root: None,
}
2023-01-20T09:54:27.628212Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 130
2023-01-20T09:54:27.628239Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::130
2023-01-20T09:54:27.628246Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.628253Z  INFO evm_eth_compliance::statetest::runner: TX len : 50
2023-01-20T09:54:27.628260Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.629321Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910209,
    events_root: None,
}
2023-01-20T09:54:27.629355Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 131
2023-01-20T09:54:27.629388Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::131
2023-01-20T09:54:27.629395Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.629402Z  INFO evm_eth_compliance::statetest::runner: TX len : 48
2023-01-20T09:54:27.629408Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.630540Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910183,
    events_root: None,
}
2023-01-20T09:54:27.630576Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 132
2023-01-20T09:54:27.630610Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::132
2023-01-20T09:54:27.630617Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.630624Z  INFO evm_eth_compliance::statetest::runner: TX len : 46
2023-01-20T09:54:27.630630Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.631658Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910157,
    events_root: None,
}
2023-01-20T09:54:27.631689Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 133
2023-01-20T09:54:27.631717Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::133
2023-01-20T09:54:27.631723Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.631730Z  INFO evm_eth_compliance::statetest::runner: TX len : 44
2023-01-20T09:54:27.631736Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.632743Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910130,
    events_root: None,
}
2023-01-20T09:54:27.632774Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 134
2023-01-20T09:54:27.632802Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::134
2023-01-20T09:54:27.632809Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.632816Z  INFO evm_eth_compliance::statetest::runner: TX len : 47
2023-01-20T09:54:27.632822Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.633835Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910170,
    events_root: None,
}
2023-01-20T09:54:27.633866Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 135
2023-01-20T09:54:27.633894Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::135
2023-01-20T09:54:27.633900Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.633907Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T09:54:27.633913Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.634920Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2914475,
    events_root: None,
}
2023-01-20T09:54:27.634950Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 136
2023-01-20T09:54:27.634978Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::136
2023-01-20T09:54:27.634985Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.634992Z  INFO evm_eth_compliance::statetest::runner: TX len : 58
2023-01-20T09:54:27.634998Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.636010Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2914567,
    events_root: None,
}
2023-01-20T09:54:27.636040Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 137
2023-01-20T09:54:27.636067Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::137
2023-01-20T09:54:27.636075Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.636082Z  INFO evm_eth_compliance::statetest::runner: TX len : 50
2023-01-20T09:54:27.636088Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.637109Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910209,
    events_root: None,
}
2023-01-20T09:54:27.637139Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 138
2023-01-20T09:54:27.637167Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::138
2023-01-20T09:54:27.637174Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.637181Z  INFO evm_eth_compliance::statetest::runner: TX len : 50
2023-01-20T09:54:27.637187Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.638197Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910209,
    events_root: None,
}
2023-01-20T09:54:27.638238Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 139
2023-01-20T09:54:27.638267Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::139
2023-01-20T09:54:27.638275Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.638282Z  INFO evm_eth_compliance::statetest::runner: TX len : 44
2023-01-20T09:54:27.638288Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.639297Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910130,
    events_root: None,
}
2023-01-20T09:54:27.639327Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 140
2023-01-20T09:54:27.639355Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::140
2023-01-20T09:54:27.639362Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.639370Z  INFO evm_eth_compliance::statetest::runner: TX len : 52
2023-01-20T09:54:27.639376Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.640380Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2914488,
    events_root: None,
}
2023-01-20T09:54:27.640411Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 141
2023-01-20T09:54:27.640438Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::141
2023-01-20T09:54:27.640445Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.640452Z  INFO evm_eth_compliance::statetest::runner: TX len : 53
2023-01-20T09:54:27.640458Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.641471Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2914501,
    events_root: None,
}
2023-01-20T09:54:27.641501Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 142
2023-01-20T09:54:27.641529Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::142
2023-01-20T09:54:27.641536Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.641543Z  INFO evm_eth_compliance::statetest::runner: TX len : 53
2023-01-20T09:54:27.641549Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.642556Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2914501,
    events_root: None,
}
2023-01-20T09:54:27.642586Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 143
2023-01-20T09:54:27.642615Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::143
2023-01-20T09:54:27.642621Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.642628Z  INFO evm_eth_compliance::statetest::runner: TX len : 53
2023-01-20T09:54:27.642634Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.643644Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2914501,
    events_root: None,
}
2023-01-20T09:54:27.643674Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 144
2023-01-20T09:54:27.643702Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::144
2023-01-20T09:54:27.643709Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.643716Z  INFO evm_eth_compliance::statetest::runner: TX len : 47
2023-01-20T09:54:27.643722Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.644738Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910170,
    events_root: None,
}
2023-01-20T09:54:27.644768Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 145
2023-01-20T09:54:27.644795Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::145
2023-01-20T09:54:27.644803Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.644810Z  INFO evm_eth_compliance::statetest::runner: TX len : 48
2023-01-20T09:54:27.644816Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.645827Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910183,
    events_root: None,
}
2023-01-20T09:54:27.645858Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 146
2023-01-20T09:54:27.645885Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::146
2023-01-20T09:54:27.645892Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.645900Z  INFO evm_eth_compliance::statetest::runner: TX len : 43
2023-01-20T09:54:27.645906Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.646911Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910117,
    events_root: None,
}
2023-01-20T09:54:27.646942Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 147
2023-01-20T09:54:27.646969Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::147
2023-01-20T09:54:27.646976Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.646983Z  INFO evm_eth_compliance::statetest::runner: TX len : 44
2023-01-20T09:54:27.646989Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.647995Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910130,
    events_root: None,
}
2023-01-20T09:54:27.648025Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 148
2023-01-20T09:54:27.648053Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::148
2023-01-20T09:54:27.648060Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.648067Z  INFO evm_eth_compliance::statetest::runner: TX len : 45
2023-01-20T09:54:27.648073Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.649086Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910143,
    events_root: None,
}
2023-01-20T09:54:27.649116Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 149
2023-01-20T09:54:27.649144Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::149
2023-01-20T09:54:27.649151Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.649158Z  INFO evm_eth_compliance::statetest::runner: TX len : 52
2023-01-20T09:54:27.649164Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.650195Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2914488,
    events_root: None,
}
2023-01-20T09:54:27.650226Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 150
2023-01-20T09:54:27.650257Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::150
2023-01-20T09:54:27.650264Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.650271Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T09:54:27.650277Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.651428Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2914475,
    events_root: None,
}
2023-01-20T09:54:27.651465Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 151
2023-01-20T09:54:27.651509Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::151
2023-01-20T09:54:27.651520Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.651529Z  INFO evm_eth_compliance::statetest::runner: TX len : 54
2023-01-20T09:54:27.651539Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.652602Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2914514,
    events_root: None,
}
2023-01-20T09:54:27.652636Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 152
2023-01-20T09:54:27.652665Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::152
2023-01-20T09:54:27.652672Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.652679Z  INFO evm_eth_compliance::statetest::runner: TX len : 56
2023-01-20T09:54:27.652685Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.653706Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2914541,
    events_root: None,
}
2023-01-20T09:54:27.653737Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 153
2023-01-20T09:54:27.653765Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::153
2023-01-20T09:54:27.653772Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.653779Z  INFO evm_eth_compliance::statetest::runner: TX len : 58
2023-01-20T09:54:27.653785Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.654798Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2914567,
    events_root: None,
}
2023-01-20T09:54:27.654829Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 154
2023-01-20T09:54:27.654857Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::154
2023-01-20T09:54:27.654863Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.654871Z  INFO evm_eth_compliance::statetest::runner: TX len : 65
2023-01-20T09:54:27.654877Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.655893Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2913844,
    events_root: None,
}
2023-01-20T09:54:27.655923Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 155
2023-01-20T09:54:27.655951Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::155
2023-01-20T09:54:27.655958Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.655965Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.655972Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.657006Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910607,
    events_root: None,
}
2023-01-20T09:54:27.657036Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 156
2023-01-20T09:54:27.657064Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::156
2023-01-20T09:54:27.657072Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.657079Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.657085Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.658097Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910607,
    events_root: None,
}
2023-01-20T09:54:27.658128Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 157
2023-01-20T09:54:27.658155Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::157
2023-01-20T09:54:27.658162Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.658170Z  INFO evm_eth_compliance::statetest::runner: TX len : 41
2023-01-20T09:54:27.658176Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.659180Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910607,
    events_root: None,
}
2023-01-20T09:54:27.659211Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 158
2023-01-20T09:54:27.659238Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::158
2023-01-20T09:54:27.659245Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.659252Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T09:54:27.659258Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.660296Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2914475,
    events_root: None,
}
2023-01-20T09:54:27.660327Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 159
2023-01-20T09:54:27.660355Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::159
2023-01-20T09:54:27.660362Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.660372Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T09:54:27.660380Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.661397Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2914475,
    events_root: None,
}
2023-01-20T09:54:27.661428Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 160
2023-01-20T09:54:27.661455Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::160
2023-01-20T09:54:27.661463Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.661470Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T09:54:27.661476Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.662486Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2914475,
    events_root: None,
}
2023-01-20T09:54:27.662516Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 161
2023-01-20T09:54:27.662544Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::161
2023-01-20T09:54:27.662551Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.662558Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T09:54:27.662565Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.663570Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2914475,
    events_root: None,
}
2023-01-20T09:54:27.663601Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 162
2023-01-20T09:54:27.663629Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::162
2023-01-20T09:54:27.663635Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.663642Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T09:54:27.663648Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.664654Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2914475,
    events_root: None,
}
2023-01-20T09:54:27.664684Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 163
2023-01-20T09:54:27.664712Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::163
2023-01-20T09:54:27.664719Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.664726Z  INFO evm_eth_compliance::statetest::runner: TX len : 51
2023-01-20T09:54:27.664732Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.665748Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2914475,
    events_root: None,
}
2023-01-20T09:54:27.665778Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 164
2023-01-20T09:54:27.665806Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::164
2023-01-20T09:54:27.665813Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.665820Z  INFO evm_eth_compliance::statetest::runner: TX len : 55
2023-01-20T09:54:27.665826Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.666828Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2914527,
    events_root: None,
}
2023-01-20T09:54:27.666860Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 165
2023-01-20T09:54:27.666887Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::165
2023-01-20T09:54:27.666894Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.666901Z  INFO evm_eth_compliance::statetest::runner: TX len : 55
2023-01-20T09:54:27.666907Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.667911Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2914527,
    events_root: None,
}
2023-01-20T09:54:27.667942Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 166
2023-01-20T09:54:27.667970Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::166
2023-01-20T09:54:27.667977Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.667984Z  INFO evm_eth_compliance::statetest::runner: TX len : 55
2023-01-20T09:54:27.667990Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.669039Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2914527,
    events_root: None,
}
2023-01-20T09:54:27.669077Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 167
2023-01-20T09:54:27.669111Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::167
2023-01-20T09:54:27.669120Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.669129Z  INFO evm_eth_compliance::statetest::runner: TX len : 24
2023-01-20T09:54:27.669136Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.670177Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2910861,
    events_root: None,
}
2023-01-20T09:54:27.670211Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Shanghai 168
2023-01-20T09:54:27.670244Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CREATE2_EOF1Invalid"::Shanghai::168
2023-01-20T09:54:27.670251Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.670259Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-20T09:54:27.670265Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[DEBUG] fetching parameters block: 1
[DEBUG] fetching parameters block: 1
2023-01-20T09:54:27.671395Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2914083,
    events_root: None,
}
2023-01-20T09:54:27.673264Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/EIPTests/stEOF/stEIP3540/CREATE2_EOF1Invalid.json"
2023-01-20T09:54:27.673533Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:12.340450855s
```