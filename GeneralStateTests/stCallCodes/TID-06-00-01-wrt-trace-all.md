> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCallCodes

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCallCodes \
	cargo run --release \
	-- \
	statetest
```

> For Review

* Following use-cases are failed

- Hit with error `EVM_CONTRACT_UNDEFINED_INSTRUCTION` (ExitCode::35)

| Test ID | Use-Case |
| --- | --- |
| TID-06-75 | callcodeEmptycontract |
| TID-06-39 | callcodecall_10 |
| TID-06-40 | callcodecall_10_OOGE |
| TID-06-41 | callcodecall_10_SuicideEnd |
| TID-06-42 | callcodecallcall_100 |
| TID-06-43 | callcodecallcall_100_OOGE |
| TID-06-44 | callcodecallcall_100_OOGMAfter |
| TID-06-45 | callcodecallcall_100_OOGMBefore |
| TID-06-46 | callcodecallcall_100_SuicideEnd |
| TID-06-47 | callcodecallcall_100_SuicideMiddle |
| TID-06-48 | callcodecallcall_ABCB_RECURSIVE |
| TID-06-49 | callcodecallcallcode_101 |
| TID-06-50 | callcodecallcallcode_101_OOGE |
| TID-06-51 | callcodecallcallcode_101_OOGMAfter |
| TID-06-52 | callcodecallcallcode_101_OOGMBefore |
| TID-06-53 | callcodecallcallcode_101_SuicideEnd |
| TID-06-54 | callcodecallcallcode_101_SuicideMiddle |
| TID-06-55 | callcodecallcallcode_ABCB_RECURSIVE |
| TID-06-56 | callcodecallcode_11 |
| TID-06-57 | callcodecallcode_11_OOGE |
| TID-06-58 | callcodecallcode_11_SuicideEnd |
| TID-06-59 | callcodecallcodecall_110 |
| TID-06-60 | callcodecallcodecall_110_OOGE |
| TID-06-61 | callcodecallcodecall_110_OOGMAfter |
| TID-06-62 | callcodecallcodecall_110_OOGMBefore |
| TID-06-63 | callcodecallcodecall_110_SuicideEnd |
| TID-06-64 | callcodecallcodecall_110_SuicideMiddle |
| TID-06-65 | callcodecallcodecall_ABCB_RECURSIVE |
| TID-06-66 | callcodecallcodecallcode_111 |
| TID-06-67 | callcodecallcodecallcode_111_OOGE |
| TID-06-68 | callcodecallcodecallcode_111_OOGMAfter |
| TID-06-69 | callcodecallcodecallcode_111_OOGMBefore |
| TID-06-70 | callcodecallcodecallcode_111_SuicideEnd |
| TID-06-71 | callcodecallcodecallcode_111_SuicideMiddle |
| TID-06-72 | callcodecallcodecallcode_ABCB_RECURSIVE |

> Execution Trace

```
2023-01-27T01:19:17.034328Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/call_OOG_additionalGasCosts1.json", Total Files :: 1
2023-01-27T01:19:17.121390Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:17.121548Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:17.121552Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:17.121605Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:17.121608Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:17.121670Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:17.121673Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:17.121731Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:17.121810Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:17.121813Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "call_OOG_additionalGasCosts1"::Istanbul::0
2023-01-27T01:19:17.121817Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/call_OOG_additionalGasCosts1.json"
2023-01-27T01:19:17.121821Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:17.121822Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:17.473674Z  INFO evm_eth_compliance::statetest::runner: UC : "call_OOG_additionalGasCosts1"
2023-01-27T01:19:17.473689Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1724909,
    events_root: None,
}
2023-01-27T01:19:17.473702Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:17.473705Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "call_OOG_additionalGasCosts1"::Berlin::0
2023-01-27T01:19:17.473707Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/call_OOG_additionalGasCosts1.json"
2023-01-27T01:19:17.473710Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:17.473711Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:17.473835Z  INFO evm_eth_compliance::statetest::runner: UC : "call_OOG_additionalGasCosts1"
2023-01-27T01:19:17.473839Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1724909,
    events_root: None,
}
2023-01-27T01:19:17.473846Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:17.473848Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "call_OOG_additionalGasCosts1"::London::0
2023-01-27T01:19:17.473850Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/call_OOG_additionalGasCosts1.json"
2023-01-27T01:19:17.473853Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:17.473854Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:17.473970Z  INFO evm_eth_compliance::statetest::runner: UC : "call_OOG_additionalGasCosts1"
2023-01-27T01:19:17.473974Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1724909,
    events_root: None,
}
2023-01-27T01:19:17.473981Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:17.473983Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "call_OOG_additionalGasCosts1"::Merge::0
2023-01-27T01:19:17.473985Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/call_OOG_additionalGasCosts1.json"
2023-01-27T01:19:17.473987Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:17.473989Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:17.474094Z  INFO evm_eth_compliance::statetest::runner: UC : "call_OOG_additionalGasCosts1"
2023-01-27T01:19:17.474098Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1724909,
    events_root: None,
}
2023-01-27T01:19:17.475324Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:352.720735ms
2023-01-27T01:19:17.754344Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/call_OOG_additionalGasCosts2.json", Total Files :: 1
2023-01-27T01:19:17.801986Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:17.802125Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:17.802129Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:17.802179Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:17.802181Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:17.802240Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:17.802242Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:17.802298Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:17.802371Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:17.802375Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "call_OOG_additionalGasCosts2"::Istanbul::0
2023-01-27T01:19:17.802378Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/call_OOG_additionalGasCosts2.json"
2023-01-27T01:19:17.802381Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:17.802382Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:18.157061Z  INFO evm_eth_compliance::statetest::runner: UC : "call_OOG_additionalGasCosts2"
2023-01-27T01:19:18.157077Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1734080,
    events_root: None,
}
2023-01-27T01:19:18.157089Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:18.157093Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "call_OOG_additionalGasCosts2"::Berlin::0
2023-01-27T01:19:18.157095Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/call_OOG_additionalGasCosts2.json"
2023-01-27T01:19:18.157098Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:18.157099Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:18.157220Z  INFO evm_eth_compliance::statetest::runner: UC : "call_OOG_additionalGasCosts2"
2023-01-27T01:19:18.157225Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1734080,
    events_root: None,
}
2023-01-27T01:19:18.157230Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:18.157232Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "call_OOG_additionalGasCosts2"::London::0
2023-01-27T01:19:18.157234Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/call_OOG_additionalGasCosts2.json"
2023-01-27T01:19:18.157237Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:18.157238Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:18.157361Z  INFO evm_eth_compliance::statetest::runner: UC : "call_OOG_additionalGasCosts2"
2023-01-27T01:19:18.157365Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1734080,
    events_root: None,
}
2023-01-27T01:19:18.157370Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:18.157372Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "call_OOG_additionalGasCosts2"::Merge::0
2023-01-27T01:19:18.157374Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/call_OOG_additionalGasCosts2.json"
2023-01-27T01:19:18.157378Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:18.157379Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:18.157479Z  INFO evm_eth_compliance::statetest::runner: UC : "call_OOG_additionalGasCosts2"
2023-01-27T01:19:18.157483Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1734080,
    events_root: None,
}
2023-01-27T01:19:18.159008Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:355.507193ms
2023-01-27T01:19:18.429913Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcall_00.json", Total Files :: 1
2023-01-27T01:19:18.493359Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:18.493496Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:18.493499Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:18.493551Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:18.493553Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:18.493611Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:18.493613Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:18.493666Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:18.493740Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:18.493743Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcall_00"::Istanbul::0
2023-01-27T01:19:18.493745Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcall_00.json"
2023-01-27T01:19:18.493748Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:18.493750Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:18.864023Z  INFO evm_eth_compliance::statetest::runner: UC : "callcall_00"
2023-01-27T01:19:18.864040Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-27T01:19:18.864053Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:18.864059Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcall_00"::Berlin::0
2023-01-27T01:19:18.864061Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcall_00.json"
2023-01-27T01:19:18.864065Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:18.864067Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:18.864205Z  INFO evm_eth_compliance::statetest::runner: UC : "callcall_00"
2023-01-27T01:19:18.864209Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-27T01:19:18.864216Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:18.864219Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcall_00"::London::0
2023-01-27T01:19:18.864222Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcall_00.json"
2023-01-27T01:19:18.864225Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:18.864227Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:18.864343Z  INFO evm_eth_compliance::statetest::runner: UC : "callcall_00"
2023-01-27T01:19:18.864347Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-27T01:19:18.864354Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:18.864357Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcall_00"::Merge::0
2023-01-27T01:19:18.864359Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcall_00.json"
2023-01-27T01:19:18.864362Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:18.864364Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:18.864497Z  INFO evm_eth_compliance::statetest::runner: UC : "callcall_00"
2023-01-27T01:19:18.864501Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-27T01:19:18.865979Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:371.15367ms
2023-01-27T01:19:19.132018Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcall_00_OOGE.json", Total Files :: 1
2023-01-27T01:19:19.163024Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:19.163161Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:19.163165Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:19.163218Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:19.163220Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:19.163280Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:19.163282Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:19.163338Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:19.163413Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:19.163416Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcall_00_OOGE"::Istanbul::0
2023-01-27T01:19:19.163419Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcall_00_OOGE.json"
2023-01-27T01:19:19.163422Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:19.163423Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:19.516898Z  INFO evm_eth_compliance::statetest::runner: UC : "callcall_00_OOGE"
2023-01-27T01:19:19.516914Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:19.516925Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:19.516929Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcall_00_OOGE"::Berlin::0
2023-01-27T01:19:19.516930Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcall_00_OOGE.json"
2023-01-27T01:19:19.516934Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:19.516935Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:19.517059Z  INFO evm_eth_compliance::statetest::runner: UC : "callcall_00_OOGE"
2023-01-27T01:19:19.517063Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:19.517069Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:19.517071Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcall_00_OOGE"::London::0
2023-01-27T01:19:19.517072Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcall_00_OOGE.json"
2023-01-27T01:19:19.517075Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:19.517076Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:19.517188Z  INFO evm_eth_compliance::statetest::runner: UC : "callcall_00_OOGE"
2023-01-27T01:19:19.517192Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:19.517197Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:19.517199Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcall_00_OOGE"::Merge::0
2023-01-27T01:19:19.517201Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcall_00_OOGE.json"
2023-01-27T01:19:19.517203Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:19.517205Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:19.517336Z  INFO evm_eth_compliance::statetest::runner: UC : "callcall_00_OOGE"
2023-01-27T01:19:19.517340Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:19.518575Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:354.32658ms
2023-01-27T01:19:19.798359Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcall_00_OOGE_valueTransfer.json", Total Files :: 1
2023-01-27T01:19:19.828600Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:19.828742Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:19.828746Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:19.828801Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:19.828803Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:19.828861Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:19.828863Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:19.828918Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:19.829014Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:19.829018Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcall_00_OOGE_valueTransfer"::Istanbul::0
2023-01-27T01:19:19.829020Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcall_00_OOGE_valueTransfer.json"
2023-01-27T01:19:19.829024Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:19.829025Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:20.185761Z  INFO evm_eth_compliance::statetest::runner: UC : "callcall_00_OOGE_valueTransfer"
2023-01-27T01:19:20.185775Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2528015,
    events_root: None,
}
2023-01-27T01:19:20.185787Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:20.185792Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcall_00_OOGE_valueTransfer"::Berlin::0
2023-01-27T01:19:20.185794Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcall_00_OOGE_valueTransfer.json"
2023-01-27T01:19:20.185797Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:20.185799Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:20.185977Z  INFO evm_eth_compliance::statetest::runner: UC : "callcall_00_OOGE_valueTransfer"
2023-01-27T01:19:20.185982Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2528015,
    events_root: None,
}
2023-01-27T01:19:20.185988Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:20.185990Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcall_00_OOGE_valueTransfer"::London::0
2023-01-27T01:19:20.185992Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcall_00_OOGE_valueTransfer.json"
2023-01-27T01:19:20.185994Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:20.185996Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:20.186157Z  INFO evm_eth_compliance::statetest::runner: UC : "callcall_00_OOGE_valueTransfer"
2023-01-27T01:19:20.186162Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2528015,
    events_root: None,
}
2023-01-27T01:19:20.186168Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:20.186170Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcall_00_OOGE_valueTransfer"::Merge::0
2023-01-27T01:19:20.186172Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcall_00_OOGE_valueTransfer.json"
2023-01-27T01:19:20.186175Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:20.186176Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:20.186335Z  INFO evm_eth_compliance::statetest::runner: UC : "callcall_00_OOGE_valueTransfer"
2023-01-27T01:19:20.186341Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2528015,
    events_root: None,
}
2023-01-27T01:19:20.187891Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:357.752631ms
2023-01-27T01:19:20.442549Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcall_00_SuicideEnd.json", Total Files :: 1
2023-01-27T01:19:20.498558Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:20.498699Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:20.498703Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:20.498755Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:20.498757Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:20.498816Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:20.498819Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:20.498876Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:20.498949Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:20.498953Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcall_00_SuicideEnd"::Istanbul::0
2023-01-27T01:19:20.498955Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcall_00_SuicideEnd.json"
2023-01-27T01:19:20.498959Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:20.498960Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:20.861470Z  INFO evm_eth_compliance::statetest::runner: UC : "callcall_00_SuicideEnd"
2023-01-27T01:19:20.861486Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:20.861499Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:20.861504Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcall_00_SuicideEnd"::Berlin::0
2023-01-27T01:19:20.861506Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcall_00_SuicideEnd.json"
2023-01-27T01:19:20.861508Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:20.861510Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:20.861644Z  INFO evm_eth_compliance::statetest::runner: UC : "callcall_00_SuicideEnd"
2023-01-27T01:19:20.861652Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:20.861658Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:20.861661Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcall_00_SuicideEnd"::London::0
2023-01-27T01:19:20.861663Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcall_00_SuicideEnd.json"
2023-01-27T01:19:20.861667Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:20.861669Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:20.861807Z  INFO evm_eth_compliance::statetest::runner: UC : "callcall_00_SuicideEnd"
2023-01-27T01:19:20.861812Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:20.861817Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:20.861819Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcall_00_SuicideEnd"::Merge::0
2023-01-27T01:19:20.861821Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcall_00_SuicideEnd.json"
2023-01-27T01:19:20.861824Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:20.861826Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:20.861940Z  INFO evm_eth_compliance::statetest::runner: UC : "callcall_00_SuicideEnd"
2023-01-27T01:19:20.861945Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:20.863678Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:363.398002ms
2023-01-27T01:19:21.135476Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000.json", Total Files :: 1
2023-01-27T01:19:21.166584Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:21.166719Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:21.166723Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:21.166773Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:21.166775Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:21.166833Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:21.166835Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:21.166890Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:21.166892Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:21.166942Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:21.167016Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:21.167019Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcall_000"::Istanbul::0
2023-01-27T01:19:21.167022Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000.json"
2023-01-27T01:19:21.167025Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:21.167026Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:21.513101Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcall_000"
2023-01-27T01:19:21.513116Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-27T01:19:21.513129Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:21.513133Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcall_000"::Berlin::0
2023-01-27T01:19:21.513136Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000.json"
2023-01-27T01:19:21.513139Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:21.513141Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:21.513267Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcall_000"
2023-01-27T01:19:21.513272Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-27T01:19:21.513279Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:21.513281Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcall_000"::London::0
2023-01-27T01:19:21.513284Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000.json"
2023-01-27T01:19:21.513287Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:21.513290Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:21.513405Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcall_000"
2023-01-27T01:19:21.513410Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-27T01:19:21.513417Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:21.513419Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcall_000"::Merge::0
2023-01-27T01:19:21.513421Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000.json"
2023-01-27T01:19:21.513424Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:21.513426Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:21.513542Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcall_000"
2023-01-27T01:19:21.513546Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-27T01:19:21.515116Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:346.973642ms
2023-01-27T01:19:21.788806Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000_OOGE.json", Total Files :: 1
2023-01-27T01:19:21.842727Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:21.842864Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:21.842867Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:21.842921Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:21.842922Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:21.842982Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:21.842984Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:21.843041Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:21.843043Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:21.843095Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:21.843172Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:21.843175Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcall_000_OOGE"::Istanbul::0
2023-01-27T01:19:21.843178Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000_OOGE.json"
2023-01-27T01:19:21.843181Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:21.843182Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:22.213272Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcall_000_OOGE"
2023-01-27T01:19:22.213289Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-27T01:19:22.213302Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:22.213308Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcall_000_OOGE"::Berlin::0
2023-01-27T01:19:22.213310Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000_OOGE.json"
2023-01-27T01:19:22.213314Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:22.213315Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:22.213516Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcall_000_OOGE"
2023-01-27T01:19:22.213522Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-27T01:19:22.213528Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:22.213531Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcall_000_OOGE"::London::0
2023-01-27T01:19:22.213533Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000_OOGE.json"
2023-01-27T01:19:22.213536Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:22.213538Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:22.213702Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcall_000_OOGE"
2023-01-27T01:19:22.213706Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-27T01:19:22.213712Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:22.213714Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcall_000_OOGE"::Merge::0
2023-01-27T01:19:22.213716Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000_OOGE.json"
2023-01-27T01:19:22.213719Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:22.213720Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:22.213907Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcall_000_OOGE"
2023-01-27T01:19:22.213914Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-27T01:19:22.215586Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:371.199947ms
2023-01-27T01:19:22.478078Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000_OOGMAfter.json", Total Files :: 1
2023-01-27T01:19:22.541102Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:22.541246Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:22.541251Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:22.541306Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:22.541309Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:22.541373Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:22.541376Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:22.541439Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:22.541442Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:22.541508Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:22.541585Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:22.541587Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcall_000_OOGMAfter"::Istanbul::0
2023-01-27T01:19:22.541590Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000_OOGMAfter.json"
2023-01-27T01:19:22.541593Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:22.541595Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:22.881671Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcall_000_OOGMAfter"
2023-01-27T01:19:22.881685Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3457188,
    events_root: None,
}
2023-01-27T01:19:22.881698Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:22.881702Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcall_000_OOGMAfter"::Berlin::0
2023-01-27T01:19:22.881704Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000_OOGMAfter.json"
2023-01-27T01:19:22.881707Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:22.881709Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:22.881891Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcall_000_OOGMAfter"
2023-01-27T01:19:22.881895Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2558154,
    events_root: None,
}
2023-01-27T01:19:22.881902Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:22.881904Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcall_000_OOGMAfter"::London::0
2023-01-27T01:19:22.881906Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000_OOGMAfter.json"
2023-01-27T01:19:22.881908Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:22.881910Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:22.882072Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcall_000_OOGMAfter"
2023-01-27T01:19:22.882076Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2558154,
    events_root: None,
}
2023-01-27T01:19:22.882082Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:22.882085Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcall_000_OOGMAfter"::Merge::0
2023-01-27T01:19:22.882087Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000_OOGMAfter.json"
2023-01-27T01:19:22.882089Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:22.882091Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:22.882256Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcall_000_OOGMAfter"
2023-01-27T01:19:22.882261Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2558154,
    events_root: None,
}
2023-01-27T01:19:22.883814Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:341.17107ms
2023-01-27T01:19:23.166680Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000_OOGMBefore.json", Total Files :: 1
2023-01-27T01:19:23.226809Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:23.226950Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:23.226954Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:23.227007Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:23.227009Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:23.227068Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:23.227070Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:23.227128Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:23.227130Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:23.227185Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:23.227263Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:23.227266Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcall_000_OOGMBefore"::Istanbul::0
2023-01-27T01:19:23.227269Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000_OOGMBefore.json"
2023-01-27T01:19:23.227272Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:23.227274Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:23.585925Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcall_000_OOGMBefore"
2023-01-27T01:19:23.585941Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-27T01:19:23.585953Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:23.585957Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcall_000_OOGMBefore"::Berlin::0
2023-01-27T01:19:23.585959Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000_OOGMBefore.json"
2023-01-27T01:19:23.585963Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:23.585964Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:23.586146Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcall_000_OOGMBefore"
2023-01-27T01:19:23.586151Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-27T01:19:23.586158Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:23.586161Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcall_000_OOGMBefore"::London::0
2023-01-27T01:19:23.586162Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000_OOGMBefore.json"
2023-01-27T01:19:23.586165Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:23.586166Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:23.586327Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcall_000_OOGMBefore"
2023-01-27T01:19:23.586331Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-27T01:19:23.586337Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:23.586339Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcall_000_OOGMBefore"::Merge::0
2023-01-27T01:19:23.586341Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000_OOGMBefore.json"
2023-01-27T01:19:23.586344Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:23.586345Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:23.586506Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcall_000_OOGMBefore"
2023-01-27T01:19:23.586511Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-27T01:19:23.587914Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:359.713749ms
2023-01-27T01:19:23.853124Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000_SuicideEnd.json", Total Files :: 1
2023-01-27T01:19:23.909491Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:23.909641Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:23.909645Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:23.909699Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:23.909701Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:23.909760Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:23.909762Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:23.909817Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:23.909819Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:23.909871Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:23.909955Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:23.909959Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcall_000_SuicideEnd"::Istanbul::0
2023-01-27T01:19:23.909962Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000_SuicideEnd.json"
2023-01-27T01:19:23.909965Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:23.909967Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:24.309620Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcall_000_SuicideEnd"
2023-01-27T01:19:24.309635Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:24.309648Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:24.309652Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcall_000_SuicideEnd"::Berlin::0
2023-01-27T01:19:24.309654Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000_SuicideEnd.json"
2023-01-27T01:19:24.309657Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:24.309659Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:24.309783Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcall_000_SuicideEnd"
2023-01-27T01:19:24.309787Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:24.309794Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:24.309796Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcall_000_SuicideEnd"::London::0
2023-01-27T01:19:24.309798Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000_SuicideEnd.json"
2023-01-27T01:19:24.309801Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:24.309802Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:24.309913Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcall_000_SuicideEnd"
2023-01-27T01:19:24.309918Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:24.309924Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:24.309926Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcall_000_SuicideEnd"::Merge::0
2023-01-27T01:19:24.309928Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000_SuicideEnd.json"
2023-01-27T01:19:24.309930Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:24.309932Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:24.310045Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcall_000_SuicideEnd"
2023-01-27T01:19:24.310049Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:24.311643Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:400.568031ms
2023-01-27T01:19:24.585531Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000_SuicideMiddle.json", Total Files :: 1
2023-01-27T01:19:24.616500Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:24.616650Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:24.616654Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:24.616706Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:24.616708Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:24.616767Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:24.616769Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:24.616826Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:24.616828Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:24.616886Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:24.616961Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:24.616964Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcall_000_SuicideMiddle"::Istanbul::0
2023-01-27T01:19:24.616967Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000_SuicideMiddle.json"
2023-01-27T01:19:24.616971Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:24.616972Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:24.967983Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcall_000_SuicideMiddle"
2023-01-27T01:19:24.967997Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:24.968009Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:24.968013Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcall_000_SuicideMiddle"::Berlin::0
2023-01-27T01:19:24.968014Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000_SuicideMiddle.json"
2023-01-27T01:19:24.968018Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:24.968019Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:24.968138Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcall_000_SuicideMiddle"
2023-01-27T01:19:24.968142Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:24.968148Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:24.968151Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcall_000_SuicideMiddle"::London::0
2023-01-27T01:19:24.968153Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000_SuicideMiddle.json"
2023-01-27T01:19:24.968156Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:24.968157Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:24.968267Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcall_000_SuicideMiddle"
2023-01-27T01:19:24.968271Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:24.968277Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:24.968280Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcall_000_SuicideMiddle"::Merge::0
2023-01-27T01:19:24.968281Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_000_SuicideMiddle.json"
2023-01-27T01:19:24.968284Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:24.968286Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:24.968413Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcall_000_SuicideMiddle"
2023-01-27T01:19:24.968418Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:24.970135Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:351.927998ms
2023-01-27T01:19:25.244473Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_ABCB_RECURSIVE.json", Total Files :: 1
2023-01-27T01:19:25.274951Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:25.275091Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:25.275095Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:25.275146Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:25.275149Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:25.275209Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:25.275211Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:25.275268Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:25.275345Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:25.275348Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcall_ABCB_RECURSIVE"::Istanbul::0
2023-01-27T01:19:25.275351Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_ABCB_RECURSIVE.json"
2023-01-27T01:19:25.275354Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:25.275355Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:25.618343Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcall_ABCB_RECURSIVE"
2023-01-27T01:19:25.618360Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5199360,
    events_root: None,
}
2023-01-27T01:19:25.618375Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:25.618378Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcall_ABCB_RECURSIVE"::Berlin::0
2023-01-27T01:19:25.618380Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_ABCB_RECURSIVE.json"
2023-01-27T01:19:25.618383Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:25.618384Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:25.618683Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcall_ABCB_RECURSIVE"
2023-01-27T01:19:25.618689Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4299582,
    events_root: None,
}
2023-01-27T01:19:25.618697Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:25.618700Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcall_ABCB_RECURSIVE"::London::0
2023-01-27T01:19:25.618702Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_ABCB_RECURSIVE.json"
2023-01-27T01:19:25.618706Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:25.618708Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:25.619004Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcall_ABCB_RECURSIVE"
2023-01-27T01:19:25.619010Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4299582,
    events_root: None,
}
2023-01-27T01:19:25.619020Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:25.619023Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcall_ABCB_RECURSIVE"::Merge::0
2023-01-27T01:19:25.619026Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcall_ABCB_RECURSIVE.json"
2023-01-27T01:19:25.619028Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:25.619030Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:25.619292Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcall_ABCB_RECURSIVE"
2023-01-27T01:19:25.619296Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4299582,
    events_root: None,
}
2023-01-27T01:19:25.620964Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:344.358332ms
2023-01-27T01:19:25.891491Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001.json", Total Files :: 1
2023-01-27T01:19:25.945730Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:25.945870Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:25.945874Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:25.945928Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:25.945930Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:25.945991Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:25.945993Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:25.946052Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:25.946055Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:25.946108Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:25.946185Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:25.946189Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001"::Istanbul::0
2023-01-27T01:19:25.946192Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001.json"
2023-01-27T01:19:25.946196Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:25.946198Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:26.355789Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001"
2023-01-27T01:19:26.355802Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-27T01:19:26.355812Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:26.355816Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001"::Berlin::0
2023-01-27T01:19:26.355818Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001.json"
2023-01-27T01:19:26.355821Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:26.355822Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:26.355946Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001"
2023-01-27T01:19:26.355950Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-27T01:19:26.355956Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:26.355958Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001"::London::0
2023-01-27T01:19:26.355960Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001.json"
2023-01-27T01:19:26.355963Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:26.355964Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:26.356076Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001"
2023-01-27T01:19:26.356080Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-27T01:19:26.356085Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:26.356088Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001"::Merge::0
2023-01-27T01:19:26.356090Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001.json"
2023-01-27T01:19:26.356092Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:26.356093Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:26.356226Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001"
2023-01-27T01:19:26.356230Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-27T01:19:26.357737Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:410.509327ms
2023-01-27T01:19:26.631973Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_OOGE.json", Total Files :: 1
2023-01-27T01:19:26.664821Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:26.665003Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:26.665009Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:26.665080Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:26.665085Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:26.665165Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:26.665170Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:26.665248Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:26.665252Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:26.665317Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:26.665399Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:26.665402Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_OOGE"::Istanbul::0
2023-01-27T01:19:26.665406Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_OOGE.json"
2023-01-27T01:19:26.665409Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:26.665411Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:27.011290Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_OOGE"
2023-01-27T01:19:27.011306Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-27T01:19:27.011320Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:27.011325Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_OOGE"::Berlin::0
2023-01-27T01:19:27.011327Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_OOGE.json"
2023-01-27T01:19:27.011329Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:27.011331Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:27.011507Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_OOGE"
2023-01-27T01:19:27.011511Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-27T01:19:27.011518Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:27.011520Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_OOGE"::London::0
2023-01-27T01:19:27.011522Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_OOGE.json"
2023-01-27T01:19:27.011524Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:27.011525Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:27.011709Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_OOGE"
2023-01-27T01:19:27.011713Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-27T01:19:27.011719Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:27.011722Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_OOGE"::Merge::0
2023-01-27T01:19:27.011723Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_OOGE.json"
2023-01-27T01:19:27.011726Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:27.011727Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:27.011890Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_OOGE"
2023-01-27T01:19:27.011895Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-27T01:19:27.013600Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:347.085511ms
2023-01-27T01:19:27.300433Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_OOGMAfter.json", Total Files :: 1
2023-01-27T01:19:27.332414Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:27.332562Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:27.332566Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:27.332625Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:27.332628Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:27.332694Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:27.332697Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:27.332760Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:27.332763Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:27.332818Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:27.332893Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:27.332897Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_OOGMAfter"::Istanbul::0
2023-01-27T01:19:27.332900Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_OOGMAfter.json"
2023-01-27T01:19:27.332904Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:27.332906Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:27.693800Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_OOGMAfter"
2023-01-27T01:19:27.693818Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3457188,
    events_root: None,
}
2023-01-27T01:19:27.693834Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:27.693839Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_OOGMAfter"::Berlin::0
2023-01-27T01:19:27.693842Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_OOGMAfter.json"
2023-01-27T01:19:27.693846Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:27.693848Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:27.694107Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_OOGMAfter"
2023-01-27T01:19:27.694113Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2558154,
    events_root: None,
}
2023-01-27T01:19:27.694123Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:27.694126Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_OOGMAfter"::London::0
2023-01-27T01:19:27.694129Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_OOGMAfter.json"
2023-01-27T01:19:27.694133Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:27.694135Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:27.694376Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_OOGMAfter"
2023-01-27T01:19:27.694381Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2558154,
    events_root: None,
}
2023-01-27T01:19:27.694391Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:27.694394Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_OOGMAfter"::Merge::0
2023-01-27T01:19:27.694397Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_OOGMAfter.json"
2023-01-27T01:19:27.694401Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:27.694403Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:27.694643Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_OOGMAfter"
2023-01-27T01:19:27.694649Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2558154,
    events_root: None,
}
2023-01-27T01:19:27.696734Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:362.24967ms
2023-01-27T01:19:27.975815Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_OOGMBefore.json", Total Files :: 1
2023-01-27T01:19:28.041237Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:28.041398Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:28.041402Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:28.041457Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:28.041459Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:28.041519Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:28.041522Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:28.041581Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:28.041583Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:28.041636Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:28.041719Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:28.041722Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_OOGMBefore"::Istanbul::0
2023-01-27T01:19:28.041725Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_OOGMBefore.json"
2023-01-27T01:19:28.041729Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:28.041731Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:28.446146Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_OOGMBefore"
2023-01-27T01:19:28.446161Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-27T01:19:28.446174Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:28.446178Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_OOGMBefore"::Berlin::0
2023-01-27T01:19:28.446179Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_OOGMBefore.json"
2023-01-27T01:19:28.446183Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:28.446184Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:28.446359Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_OOGMBefore"
2023-01-27T01:19:28.446364Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-27T01:19:28.446370Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:28.446372Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_OOGMBefore"::London::0
2023-01-27T01:19:28.446374Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_OOGMBefore.json"
2023-01-27T01:19:28.446377Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:28.446378Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:28.446541Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_OOGMBefore"
2023-01-27T01:19:28.446545Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-27T01:19:28.446551Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:28.446553Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_OOGMBefore"::Merge::0
2023-01-27T01:19:28.446555Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_OOGMBefore.json"
2023-01-27T01:19:28.446558Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:28.446559Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:28.446717Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_OOGMBefore"
2023-01-27T01:19:28.446722Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-27T01:19:28.448229Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:405.496926ms
2023-01-27T01:19:28.707611Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_SuicideEnd.json", Total Files :: 1
2023-01-27T01:19:28.738893Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:28.739043Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:28.739047Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:28.739102Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:28.739104Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:28.739164Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:28.739167Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:28.739224Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:28.739226Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:28.739280Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:28.739375Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:28.739378Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_SuicideEnd"::Istanbul::0
2023-01-27T01:19:28.739382Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_SuicideEnd.json"
2023-01-27T01:19:28.739386Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:28.739388Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:29.104872Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_SuicideEnd"
2023-01-27T01:19:29.104889Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:29.104905Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:29.104910Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_SuicideEnd"::Berlin::0
2023-01-27T01:19:29.104912Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_SuicideEnd.json"
2023-01-27T01:19:29.104916Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:29.104919Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:29.105083Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_SuicideEnd"
2023-01-27T01:19:29.105088Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:29.105097Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:29.105100Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_SuicideEnd"::London::0
2023-01-27T01:19:29.105102Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_SuicideEnd.json"
2023-01-27T01:19:29.105106Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:29.105108Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:29.105247Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_SuicideEnd"
2023-01-27T01:19:29.105253Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:29.105261Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:29.105263Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_SuicideEnd"::Merge::0
2023-01-27T01:19:29.105266Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_SuicideEnd.json"
2023-01-27T01:19:29.105269Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:29.105271Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:29.105406Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_SuicideEnd"
2023-01-27T01:19:29.105412Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:29.107266Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:366.529732ms
2023-01-27T01:19:29.390897Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_SuicideMiddle.json", Total Files :: 1
2023-01-27T01:19:29.421689Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:29.421827Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:29.421831Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:29.421883Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:29.421885Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:29.421945Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:29.421948Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:29.422003Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:29.422006Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:29.422057Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:29.422133Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:29.422136Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_SuicideMiddle"::Istanbul::0
2023-01-27T01:19:29.422139Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_SuicideMiddle.json"
2023-01-27T01:19:29.422142Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:29.422144Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:29.772929Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_SuicideMiddle"
2023-01-27T01:19:29.772944Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:29.772956Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:29.772959Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_SuicideMiddle"::Berlin::0
2023-01-27T01:19:29.772961Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_SuicideMiddle.json"
2023-01-27T01:19:29.772965Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:29.772966Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:29.773088Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_SuicideMiddle"
2023-01-27T01:19:29.773092Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:29.773097Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:29.773099Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_SuicideMiddle"::London::0
2023-01-27T01:19:29.773102Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_SuicideMiddle.json"
2023-01-27T01:19:29.773104Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:29.773105Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:29.773215Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_SuicideMiddle"
2023-01-27T01:19:29.773220Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:29.773225Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:29.773228Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_SuicideMiddle"::Merge::0
2023-01-27T01:19:29.773230Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_001_SuicideMiddle.json"
2023-01-27T01:19:29.773233Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:29.773234Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:29.773361Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_SuicideMiddle"
2023-01-27T01:19:29.773365Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:29.774962Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:351.686832ms
2023-01-27T01:19:30.049794Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_ABCB_RECURSIVE.json", Total Files :: 1
2023-01-27T01:19:30.106685Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:30.106820Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:30.106823Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:30.106876Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:30.106878Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:30.106935Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:30.106937Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:30.106991Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:30.107066Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:30.107068Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_ABCB_RECURSIVE"::Istanbul::0
2023-01-27T01:19:30.107071Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_ABCB_RECURSIVE.json"
2023-01-27T01:19:30.107075Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:30.107076Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:30.511771Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_ABCB_RECURSIVE"
2023-01-27T01:19:30.511785Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5199360,
    events_root: None,
}
2023-01-27T01:19:30.511801Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:30.511804Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_ABCB_RECURSIVE"::Berlin::0
2023-01-27T01:19:30.511806Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_ABCB_RECURSIVE.json"
2023-01-27T01:19:30.511809Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:30.511811Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:30.512063Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_ABCB_RECURSIVE"
2023-01-27T01:19:30.512068Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4299582,
    events_root: None,
}
2023-01-27T01:19:30.512078Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:30.512081Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_ABCB_RECURSIVE"::London::0
2023-01-27T01:19:30.512083Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_ABCB_RECURSIVE.json"
2023-01-27T01:19:30.512085Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:30.512087Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:30.512322Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_ABCB_RECURSIVE"
2023-01-27T01:19:30.512326Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4299582,
    events_root: None,
}
2023-01-27T01:19:30.512337Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:30.512340Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_ABCB_RECURSIVE"::Merge::0
2023-01-27T01:19:30.512341Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcallcode_ABCB_RECURSIVE.json"
2023-01-27T01:19:30.512344Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:30.512345Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:30.512587Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_ABCB_RECURSIVE"
2023-01-27T01:19:30.512592Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4299582,
    events_root: None,
}
2023-01-27T01:19:30.514159Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:405.922534ms
2023-01-27T01:19:30.778950Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcode_01.json", Total Files :: 1
2023-01-27T01:19:30.810034Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:30.810180Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:30.810185Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:30.810240Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:30.810242Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:30.810304Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:30.810308Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:30.810366Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:30.810444Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:30.810447Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01"::Istanbul::0
2023-01-27T01:19:30.810451Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcode_01.json"
2023-01-27T01:19:30.810455Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:30.810457Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:31.182539Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcode_01"
2023-01-27T01:19:31.182554Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-27T01:19:31.182565Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:31.182570Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01"::Berlin::0
2023-01-27T01:19:31.182572Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcode_01.json"
2023-01-27T01:19:31.182574Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:31.182576Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:31.182701Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcode_01"
2023-01-27T01:19:31.182705Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-27T01:19:31.182710Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:31.182713Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01"::London::0
2023-01-27T01:19:31.182714Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcode_01.json"
2023-01-27T01:19:31.182716Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:31.182718Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:31.182831Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcode_01"
2023-01-27T01:19:31.182835Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-27T01:19:31.182840Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:31.182842Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01"::Merge::0
2023-01-27T01:19:31.182844Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcode_01.json"
2023-01-27T01:19:31.182846Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:31.182848Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:31.182974Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcode_01"
2023-01-27T01:19:31.182978Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-27T01:19:31.184490Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:372.954ms
2023-01-27T01:19:31.457957Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcode_01_OOGE.json", Total Files :: 1
2023-01-27T01:19:31.489234Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:31.489372Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:31.489375Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:31.489429Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:31.489432Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:31.489492Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:31.489494Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:31.489553Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:31.489645Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:31.489649Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01_OOGE"::Istanbul::0
2023-01-27T01:19:31.489651Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcode_01_OOGE.json"
2023-01-27T01:19:31.489654Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:31.489656Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:31.833559Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcode_01_OOGE"
2023-01-27T01:19:31.833573Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-27T01:19:31.833585Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:31.833589Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01_OOGE"::Berlin::0
2023-01-27T01:19:31.833590Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcode_01_OOGE.json"
2023-01-27T01:19:31.833593Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:31.833595Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:31.833758Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcode_01_OOGE"
2023-01-27T01:19:31.833762Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-27T01:19:31.833768Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:31.833771Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01_OOGE"::London::0
2023-01-27T01:19:31.833773Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcode_01_OOGE.json"
2023-01-27T01:19:31.833775Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:31.833777Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:31.833925Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcode_01_OOGE"
2023-01-27T01:19:31.833930Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-27T01:19:31.833935Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:31.833938Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01_OOGE"::Merge::0
2023-01-27T01:19:31.833940Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcode_01_OOGE.json"
2023-01-27T01:19:31.833942Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:31.833943Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:31.834092Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcode_01_OOGE"
2023-01-27T01:19:31.834096Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-27T01:19:31.835473Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:344.873402ms
2023-01-27T01:19:32.110942Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcode_01_SuicideEnd.json", Total Files :: 1
2023-01-27T01:19:32.141871Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:32.142011Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:32.142015Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:32.142068Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:32.142070Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:32.142130Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:32.142133Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:32.142190Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:32.142266Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:32.142270Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01_SuicideEnd"::Istanbul::0
2023-01-27T01:19:32.142273Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcode_01_SuicideEnd.json"
2023-01-27T01:19:32.142276Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:32.142278Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:32.506075Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcode_01_SuicideEnd"
2023-01-27T01:19:32.506120Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:32.506143Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:32.506154Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01_SuicideEnd"::Berlin::0
2023-01-27T01:19:32.506157Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcode_01_SuicideEnd.json"
2023-01-27T01:19:32.506161Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:32.506163Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:32.506326Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcode_01_SuicideEnd"
2023-01-27T01:19:32.506342Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:32.506364Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:32.506372Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01_SuicideEnd"::London::0
2023-01-27T01:19:32.506379Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcode_01_SuicideEnd.json"
2023-01-27T01:19:32.506387Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:32.506394Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:32.506556Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcode_01_SuicideEnd"
2023-01-27T01:19:32.506572Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:32.506587Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:32.506595Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01_SuicideEnd"::Merge::0
2023-01-27T01:19:32.506602Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcode_01_SuicideEnd.json"
2023-01-27T01:19:32.506611Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:32.506617Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:32.506806Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcode_01_SuicideEnd"
2023-01-27T01:19:32.506822Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:32.508759Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:364.971031ms
2023-01-27T01:19:32.782624Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecall_010.json", Total Files :: 1
2023-01-27T01:19:32.812598Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:32.812870Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:32.812880Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:32.813022Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:32.813029Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:32.813190Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:32.813198Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:32.813348Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:32.813355Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:32.813466Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:32.813621Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:32.813626Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010"::Istanbul::0
2023-01-27T01:19:32.813630Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecall_010.json"
2023-01-27T01:19:32.813636Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:32.813639Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:33.166210Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010"
2023-01-27T01:19:33.166226Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-27T01:19:33.166237Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:33.166241Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010"::Berlin::0
2023-01-27T01:19:33.166242Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecall_010.json"
2023-01-27T01:19:33.166245Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:33.166246Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:33.166368Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010"
2023-01-27T01:19:33.166372Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-27T01:19:33.166379Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:33.166381Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010"::London::0
2023-01-27T01:19:33.166383Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecall_010.json"
2023-01-27T01:19:33.166385Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:33.166387Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:33.166497Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010"
2023-01-27T01:19:33.166503Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-27T01:19:33.166508Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:33.166510Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010"::Merge::0
2023-01-27T01:19:33.166512Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecall_010.json"
2023-01-27T01:19:33.166514Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:33.166516Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:33.166648Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010"
2023-01-27T01:19:33.166653Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-27T01:19:33.168162Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:354.067685ms
2023-01-27T01:19:33.442699Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecall_010_OOGE.json", Total Files :: 1
2023-01-27T01:19:33.473890Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:33.474034Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:33.474038Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:33.474099Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:33.474102Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:33.474177Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:33.474180Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:33.474240Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:33.474242Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:33.474296Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:33.474375Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:33.474379Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_OOGE"::Istanbul::0
2023-01-27T01:19:33.474382Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecall_010_OOGE.json"
2023-01-27T01:19:33.474386Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:33.474387Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:33.872497Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_OOGE"
2023-01-27T01:19:33.872512Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-27T01:19:33.872523Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:33.872527Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_OOGE"::Berlin::0
2023-01-27T01:19:33.872535Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecall_010_OOGE.json"
2023-01-27T01:19:33.872539Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:33.872540Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:33.872706Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_OOGE"
2023-01-27T01:19:33.872710Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-27T01:19:33.872716Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:33.872718Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_OOGE"::London::0
2023-01-27T01:19:33.872720Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecall_010_OOGE.json"
2023-01-27T01:19:33.872722Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:33.872723Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:33.872871Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_OOGE"
2023-01-27T01:19:33.872875Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-27T01:19:33.872882Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:33.872884Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_OOGE"::Merge::0
2023-01-27T01:19:33.872886Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecall_010_OOGE.json"
2023-01-27T01:19:33.872888Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:33.872890Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:33.873036Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_OOGE"
2023-01-27T01:19:33.873040Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-27T01:19:33.874573Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:399.160537ms
2023-01-27T01:19:34.131040Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecall_010_OOGMAfter.json", Total Files :: 1
2023-01-27T01:19:34.161585Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:34.161722Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:34.161725Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:34.161776Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:34.161778Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:34.161839Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:34.161841Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:34.161894Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:34.161896Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:34.161957Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:34.162058Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:34.162063Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_OOGMAfter"::Istanbul::0
2023-01-27T01:19:34.162066Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecall_010_OOGMAfter.json"
2023-01-27T01:19:34.162070Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:34.162072Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:34.497582Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_OOGMAfter"
2023-01-27T01:19:34.497597Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3457188,
    events_root: None,
}
2023-01-27T01:19:34.497608Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:34.497612Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_OOGMAfter"::Berlin::0
2023-01-27T01:19:34.497614Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecall_010_OOGMAfter.json"
2023-01-27T01:19:34.497617Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:34.497618Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:34.497794Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_OOGMAfter"
2023-01-27T01:19:34.497799Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2558154,
    events_root: None,
}
2023-01-27T01:19:34.497805Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:34.497808Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_OOGMAfter"::London::0
2023-01-27T01:19:34.497810Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecall_010_OOGMAfter.json"
2023-01-27T01:19:34.497813Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:34.497814Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:34.497972Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_OOGMAfter"
2023-01-27T01:19:34.497977Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2558154,
    events_root: None,
}
2023-01-27T01:19:34.497983Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:34.497985Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_OOGMAfter"::Merge::0
2023-01-27T01:19:34.497987Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecall_010_OOGMAfter.json"
2023-01-27T01:19:34.497989Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:34.497991Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:34.498148Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_OOGMAfter"
2023-01-27T01:19:34.498153Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2558154,
    events_root: None,
}
2023-01-27T01:19:34.499661Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:336.578431ms
2023-01-27T01:19:34.779970Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecall_010_OOGMBefore.json", Total Files :: 1
2023-01-27T01:19:34.811882Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:34.812021Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:34.812025Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:34.812080Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:34.812082Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:34.812142Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:34.812144Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:34.812200Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:34.812203Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:34.812255Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:34.812331Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:34.812334Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_OOGMBefore"::Istanbul::0
2023-01-27T01:19:34.812337Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecall_010_OOGMBefore.json"
2023-01-27T01:19:34.812341Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:34.812342Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:35.158180Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_OOGMBefore"
2023-01-27T01:19:35.158193Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-27T01:19:35.158205Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:35.158209Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_OOGMBefore"::Berlin::0
2023-01-27T01:19:35.158211Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecall_010_OOGMBefore.json"
2023-01-27T01:19:35.158214Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:35.158215Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:35.158380Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_OOGMBefore"
2023-01-27T01:19:35.158385Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-27T01:19:35.158391Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:35.158393Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_OOGMBefore"::London::0
2023-01-27T01:19:35.158395Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecall_010_OOGMBefore.json"
2023-01-27T01:19:35.158398Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:35.158399Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:35.158575Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_OOGMBefore"
2023-01-27T01:19:35.158581Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-27T01:19:35.158587Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:35.158590Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_OOGMBefore"::Merge::0
2023-01-27T01:19:35.158592Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecall_010_OOGMBefore.json"
2023-01-27T01:19:35.158595Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:35.158597Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:35.158768Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_OOGMBefore"
2023-01-27T01:19:35.158772Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-27T01:19:35.160422Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:346.900879ms
2023-01-27T01:19:35.434491Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecall_010_SuicideEnd.json", Total Files :: 1
2023-01-27T01:19:35.466212Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:35.466351Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:35.466355Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:35.466406Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:35.466408Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:35.466464Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:35.466466Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:35.466519Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:35.466522Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:35.466571Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:35.466644Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:35.466647Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_SuicideEnd"::Istanbul::0
2023-01-27T01:19:35.466650Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecall_010_SuicideEnd.json"
2023-01-27T01:19:35.466653Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:35.466654Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:35.852128Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_SuicideEnd"
2023-01-27T01:19:35.852143Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:35.852155Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:35.852160Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_SuicideEnd"::Berlin::0
2023-01-27T01:19:35.852163Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecall_010_SuicideEnd.json"
2023-01-27T01:19:35.852167Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:35.852168Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:35.852294Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_SuicideEnd"
2023-01-27T01:19:35.852299Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:35.852306Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:35.852309Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_SuicideEnd"::London::0
2023-01-27T01:19:35.852312Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecall_010_SuicideEnd.json"
2023-01-27T01:19:35.852316Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:35.852318Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:35.852436Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_SuicideEnd"
2023-01-27T01:19:35.852441Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:35.852448Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:35.852451Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_SuicideEnd"::Merge::0
2023-01-27T01:19:35.852453Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecall_010_SuicideEnd.json"
2023-01-27T01:19:35.852456Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:35.852458Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:35.852598Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_SuicideEnd"
2023-01-27T01:19:35.852603Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:35.854045Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:386.40245ms
2023-01-27T01:19:36.128217Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecall_010_SuicideMiddle.json", Total Files :: 1
2023-01-27T01:19:36.195301Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:36.195439Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:36.195442Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:36.195494Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:36.195497Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:36.195556Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:36.195558Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:36.195613Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:36.195615Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:36.195666Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:36.195743Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:36.195746Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_SuicideMiddle"::Istanbul::0
2023-01-27T01:19:36.195749Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecall_010_SuicideMiddle.json"
2023-01-27T01:19:36.195752Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:36.195754Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:36.573254Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_SuicideMiddle"
2023-01-27T01:19:36.573270Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:36.573281Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:36.573285Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_SuicideMiddle"::Berlin::0
2023-01-27T01:19:36.573287Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecall_010_SuicideMiddle.json"
2023-01-27T01:19:36.573290Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:36.573291Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:36.573419Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_SuicideMiddle"
2023-01-27T01:19:36.573423Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:36.573429Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:36.573431Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_SuicideMiddle"::London::0
2023-01-27T01:19:36.573433Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecall_010_SuicideMiddle.json"
2023-01-27T01:19:36.573436Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:36.573437Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:36.573550Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_SuicideMiddle"
2023-01-27T01:19:36.573555Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:36.573560Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:36.573562Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_SuicideMiddle"::Merge::0
2023-01-27T01:19:36.573564Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecall_010_SuicideMiddle.json"
2023-01-27T01:19:36.573567Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:36.573568Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:36.573677Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_SuicideMiddle"
2023-01-27T01:19:36.573681Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:36.575352Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:378.391988ms
2023-01-27T01:19:36.858303Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecall_ABCB_RECURSIVE.json", Total Files :: 1
2023-01-27T01:19:36.892731Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:36.892869Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:36.892873Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:36.892925Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:36.892927Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:36.892985Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:36.892987Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:36.893046Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:36.893120Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:36.893123Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_ABCB_RECURSIVE"::Istanbul::0
2023-01-27T01:19:36.893126Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecall_ABCB_RECURSIVE.json"
2023-01-27T01:19:36.893129Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:36.893131Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:37.257435Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_ABCB_RECURSIVE"
2023-01-27T01:19:37.257450Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3101026,
    events_root: None,
}
2023-01-27T01:19:37.257462Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:37.257466Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_ABCB_RECURSIVE"::Berlin::0
2023-01-27T01:19:37.257468Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecall_ABCB_RECURSIVE.json"
2023-01-27T01:19:37.257471Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:37.257472Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:37.257663Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_ABCB_RECURSIVE"
2023-01-27T01:19:37.257667Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3101026,
    events_root: None,
}
2023-01-27T01:19:37.257674Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:37.257676Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_ABCB_RECURSIVE"::London::0
2023-01-27T01:19:37.257678Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecall_ABCB_RECURSIVE.json"
2023-01-27T01:19:37.257681Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:37.257682Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:37.257861Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_ABCB_RECURSIVE"
2023-01-27T01:19:37.257865Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3101026,
    events_root: None,
}
2023-01-27T01:19:37.257871Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:37.257874Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_ABCB_RECURSIVE"::Merge::0
2023-01-27T01:19:37.257876Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecall_ABCB_RECURSIVE.json"
2023-01-27T01:19:37.257878Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:37.257880Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:37.258054Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_ABCB_RECURSIVE"
2023-01-27T01:19:37.258058Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3101026,
    events_root: None,
}
2023-01-27T01:19:37.259485Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:365.339604ms
2023-01-27T01:19:37.539099Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecallcode_011.json", Total Files :: 1
2023-01-27T01:19:37.606922Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:37.607056Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:37.607059Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:37.607111Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:37.607113Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:37.607171Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:37.607173Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:37.607227Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:37.607229Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:37.607279Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:37.607353Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:37.607355Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011"::Istanbul::0
2023-01-27T01:19:37.607358Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecallcode_011.json"
2023-01-27T01:19:37.607361Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:37.607363Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:37.993246Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011"
2023-01-27T01:19:37.993259Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-27T01:19:37.993272Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:37.993276Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011"::Berlin::0
2023-01-27T01:19:37.993278Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecallcode_011.json"
2023-01-27T01:19:37.993281Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:37.993282Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:37.993411Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011"
2023-01-27T01:19:37.993415Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-27T01:19:37.993422Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:37.993424Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011"::London::0
2023-01-27T01:19:37.993426Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecallcode_011.json"
2023-01-27T01:19:37.993429Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:37.993430Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:37.993545Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011"
2023-01-27T01:19:37.993549Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-27T01:19:37.993556Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:37.993558Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011"::Merge::0
2023-01-27T01:19:37.993560Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecallcode_011.json"
2023-01-27T01:19:37.993564Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:37.993565Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:37.993677Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011"
2023-01-27T01:19:37.993682Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-27T01:19:37.995232Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:386.772435ms
2023-01-27T01:19:38.257353Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecallcode_011_OOGE.json", Total Files :: 1
2023-01-27T01:19:38.288184Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:38.288325Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:38.288330Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:38.288384Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:38.288386Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:38.288446Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:38.288448Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:38.288506Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:38.288508Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:38.288568Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:38.288651Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:38.288654Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_OOGE"::Istanbul::0
2023-01-27T01:19:38.288657Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecallcode_011_OOGE.json"
2023-01-27T01:19:38.288661Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:38.288662Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:38.627889Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_OOGE"
2023-01-27T01:19:38.627905Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-27T01:19:38.627918Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:38.627923Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_OOGE"::Berlin::0
2023-01-27T01:19:38.627925Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecallcode_011_OOGE.json"
2023-01-27T01:19:38.627929Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:38.627930Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:38.628122Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_OOGE"
2023-01-27T01:19:38.628128Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-27T01:19:38.628134Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:38.628136Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_OOGE"::London::0
2023-01-27T01:19:38.628138Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecallcode_011_OOGE.json"
2023-01-27T01:19:38.628141Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:38.628143Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:38.628347Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_OOGE"
2023-01-27T01:19:38.628369Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-27T01:19:38.628378Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:38.628381Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_OOGE"::Merge::0
2023-01-27T01:19:38.628383Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecallcode_011_OOGE.json"
2023-01-27T01:19:38.628387Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:38.628389Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:38.628569Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_OOGE"
2023-01-27T01:19:38.628574Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-27T01:19:38.630435Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:340.40186ms
2023-01-27T01:19:38.914323Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecallcode_011_OOGMAfter.json", Total Files :: 1
2023-01-27T01:19:38.949208Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:38.949345Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:38.949349Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:38.949400Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:38.949402Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:38.949462Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:38.949464Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:38.949518Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:38.949520Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:38.949573Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:38.949648Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:38.949651Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_OOGMAfter"::Istanbul::0
2023-01-27T01:19:38.949654Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecallcode_011_OOGMAfter.json"
2023-01-27T01:19:38.949657Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:38.949659Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:39.304191Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_OOGMAfter"
2023-01-27T01:19:39.304206Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3457188,
    events_root: None,
}
2023-01-27T01:19:39.304220Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:39.304224Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_OOGMAfter"::Berlin::0
2023-01-27T01:19:39.304227Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecallcode_011_OOGMAfter.json"
2023-01-27T01:19:39.304231Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:39.304233Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:39.304412Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_OOGMAfter"
2023-01-27T01:19:39.304417Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2558154,
    events_root: None,
}
2023-01-27T01:19:39.304425Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:39.304428Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_OOGMAfter"::London::0
2023-01-27T01:19:39.304431Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecallcode_011_OOGMAfter.json"
2023-01-27T01:19:39.304434Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:39.304436Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:39.304620Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_OOGMAfter"
2023-01-27T01:19:39.304625Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2558154,
    events_root: None,
}
2023-01-27T01:19:39.304633Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:39.304636Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_OOGMAfter"::Merge::0
2023-01-27T01:19:39.304639Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecallcode_011_OOGMAfter.json"
2023-01-27T01:19:39.304643Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:39.304645Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:39.304810Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_OOGMAfter"
2023-01-27T01:19:39.304815Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2558154,
    events_root: None,
}
2023-01-27T01:19:39.306251Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:355.619539ms
2023-01-27T01:19:39.572357Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecallcode_011_OOGMBefore.json", Total Files :: 1
2023-01-27T01:19:39.637433Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:39.637572Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:39.637576Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:39.637627Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:39.637629Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:39.637688Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:39.637690Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:39.637744Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:39.637747Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:39.637798Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:39.637872Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:39.637875Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_OOGMBefore"::Istanbul::0
2023-01-27T01:19:39.637878Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecallcode_011_OOGMBefore.json"
2023-01-27T01:19:39.637881Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:39.637883Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:39.995449Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_OOGMBefore"
2023-01-27T01:19:39.995465Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-27T01:19:39.995478Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:39.995483Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_OOGMBefore"::Berlin::0
2023-01-27T01:19:39.995485Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecallcode_011_OOGMBefore.json"
2023-01-27T01:19:39.995489Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:39.995491Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:39.995671Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_OOGMBefore"
2023-01-27T01:19:39.995676Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-27T01:19:39.995683Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:39.995686Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_OOGMBefore"::London::0
2023-01-27T01:19:39.995688Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecallcode_011_OOGMBefore.json"
2023-01-27T01:19:39.995691Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:39.995693Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:39.995875Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_OOGMBefore"
2023-01-27T01:19:39.995881Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-27T01:19:39.995888Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:39.995891Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_OOGMBefore"::Merge::0
2023-01-27T01:19:39.995893Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecallcode_011_OOGMBefore.json"
2023-01-27T01:19:39.995896Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:39.995897Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:39.996061Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_OOGMBefore"
2023-01-27T01:19:39.996066Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-27T01:19:39.997619Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:358.644119ms
2023-01-27T01:19:40.274351Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecallcode_011_SuicideEnd.json", Total Files :: 1
2023-01-27T01:19:40.362178Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:40.362316Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:40.362320Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:40.362371Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:40.362373Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:40.362431Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:40.362433Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:40.362487Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:40.362489Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:40.362555Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:40.362668Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:40.362672Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_SuicideEnd"::Istanbul::0
2023-01-27T01:19:40.362676Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecallcode_011_SuicideEnd.json"
2023-01-27T01:19:40.362681Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:40.362683Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:40.730777Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_SuicideEnd"
2023-01-27T01:19:40.730794Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:40.730807Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:40.730812Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_SuicideEnd"::Berlin::0
2023-01-27T01:19:40.730814Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecallcode_011_SuicideEnd.json"
2023-01-27T01:19:40.730817Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:40.730818Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:40.730942Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_SuicideEnd"
2023-01-27T01:19:40.730947Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:40.730953Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:40.730956Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_SuicideEnd"::London::0
2023-01-27T01:19:40.730957Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecallcode_011_SuicideEnd.json"
2023-01-27T01:19:40.730960Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:40.730961Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:40.731073Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_SuicideEnd"
2023-01-27T01:19:40.731077Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:40.731084Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:40.731087Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_SuicideEnd"::Merge::0
2023-01-27T01:19:40.731088Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecallcode_011_SuicideEnd.json"
2023-01-27T01:19:40.731091Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:40.731092Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:40.731202Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_SuicideEnd"
2023-01-27T01:19:40.731207Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:40.732778Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:369.041661ms
2023-01-27T01:19:41.005753Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecallcode_011_SuicideMiddle.json", Total Files :: 1
2023-01-27T01:19:41.053322Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:41.053483Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:41.053488Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:41.053540Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:41.053543Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:41.053601Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:41.053603Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:41.053660Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:41.053662Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:41.053714Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:41.053790Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:41.053793Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_SuicideMiddle"::Istanbul::0
2023-01-27T01:19:41.053797Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecallcode_011_SuicideMiddle.json"
2023-01-27T01:19:41.053800Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:41.053801Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:41.399606Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_SuicideMiddle"
2023-01-27T01:19:41.399626Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:41.399639Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:41.399645Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_SuicideMiddle"::Berlin::0
2023-01-27T01:19:41.399648Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecallcode_011_SuicideMiddle.json"
2023-01-27T01:19:41.399652Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:41.399654Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:41.399819Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_SuicideMiddle"
2023-01-27T01:19:41.399825Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:41.399831Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:41.399834Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_SuicideMiddle"::London::0
2023-01-27T01:19:41.399837Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecallcode_011_SuicideMiddle.json"
2023-01-27T01:19:41.399840Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:41.399842Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:41.399995Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_SuicideMiddle"
2023-01-27T01:19:41.400000Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:41.400006Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:41.400008Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_SuicideMiddle"::Merge::0
2023-01-27T01:19:41.400010Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecallcode_011_SuicideMiddle.json"
2023-01-27T01:19:41.400012Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:41.400014Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:41.400154Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_SuicideMiddle"
2023-01-27T01:19:41.400159Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-27T01:19:41.402194Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:346.848951ms
2023-01-27T01:19:41.669386Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecallcode_ABCB_RECURSIVE.json", Total Files :: 1
2023-01-27T01:19:41.707540Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:41.707684Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:41.707688Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:41.707741Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:41.707743Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:41.707802Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:41.707804Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:41.707862Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:41.707937Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:41.707940Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_ABCB_RECURSIVE"::Istanbul::0
2023-01-27T01:19:41.707943Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecallcode_ABCB_RECURSIVE.json"
2023-01-27T01:19:41.707947Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:41.707949Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:42.072064Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_ABCB_RECURSIVE"
2023-01-27T01:19:42.072084Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3101026,
    events_root: None,
}
2023-01-27T01:19:42.072099Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:42.072104Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_ABCB_RECURSIVE"::Berlin::0
2023-01-27T01:19:42.072108Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecallcode_ABCB_RECURSIVE.json"
2023-01-27T01:19:42.072112Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:42.072113Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:42.072374Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_ABCB_RECURSIVE"
2023-01-27T01:19:42.072380Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3101026,
    events_root: None,
}
2023-01-27T01:19:42.072388Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:42.072391Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_ABCB_RECURSIVE"::London::0
2023-01-27T01:19:42.072394Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecallcode_ABCB_RECURSIVE.json"
2023-01-27T01:19:42.072397Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:42.072399Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:42.072663Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_ABCB_RECURSIVE"
2023-01-27T01:19:42.072669Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3101026,
    events_root: None,
}
2023-01-27T01:19:42.072677Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:42.072680Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_ABCB_RECURSIVE"::Merge::0
2023-01-27T01:19:42.072682Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcallcodecallcode_ABCB_RECURSIVE.json"
2023-01-27T01:19:42.072685Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:42.072687Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:42.072942Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_ABCB_RECURSIVE"
2023-01-27T01:19:42.072962Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3101026,
    events_root: None,
}
2023-01-27T01:19:42.075026Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:365.44439ms
2023-01-27T01:19:42.348384Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeDynamicCode.json", Total Files :: 1
2023-01-27T01:19:42.422127Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:42.422318Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:42.422322Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:42.422400Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:42.422404Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:42.422489Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:42.422493Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:42.422575Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:42.422579Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:42.422654Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:42.422657Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 5
2023-01-27T01:19:42.422753Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:42.422867Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:42.422872Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeDynamicCode"::Istanbul::0
2023-01-27T01:19:42.422878Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeDynamicCode.json"
2023-01-27T01:19:42.422882Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:42.422885Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:42.778542Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeDynamicCode"
2023-01-27T01:19:42.778557Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2505433,
    events_root: None,
}
2023-01-27T01:19:42.778568Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-27T01:19:42.778573Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeDynamicCode"::Istanbul::1
2023-01-27T01:19:42.778575Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeDynamicCode.json"
2023-01-27T01:19:42.778577Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:42.778579Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:42.778755Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeDynamicCode"
2023-01-27T01:19:42.778760Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2505433,
    events_root: None,
}
2023-01-27T01:19:42.778765Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 2
2023-01-27T01:19:42.778768Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeDynamicCode"::Istanbul::2
2023-01-27T01:19:42.778769Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeDynamicCode.json"
2023-01-27T01:19:42.778772Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:42.778773Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:42.778932Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeDynamicCode"
2023-01-27T01:19:42.778937Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2505433,
    events_root: None,
}
2023-01-27T01:19:42.778943Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 3
2023-01-27T01:19:42.778946Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeDynamicCode"::Istanbul::3
2023-01-27T01:19:42.778947Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeDynamicCode.json"
2023-01-27T01:19:42.778950Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:42.778952Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:42.779110Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeDynamicCode"
2023-01-27T01:19:42.779114Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2505433,
    events_root: None,
}
2023-01-27T01:19:42.779120Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:42.779123Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeDynamicCode"::Berlin::0
2023-01-27T01:19:42.779124Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeDynamicCode.json"
2023-01-27T01:19:42.779127Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:42.779128Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:42.779340Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeDynamicCode"
2023-01-27T01:19:42.779346Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2505433,
    events_root: None,
}
2023-01-27T01:19:42.779353Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-27T01:19:42.779356Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeDynamicCode"::Berlin::1
2023-01-27T01:19:42.779359Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeDynamicCode.json"
2023-01-27T01:19:42.779363Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:42.779365Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:42.779538Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeDynamicCode"
2023-01-27T01:19:42.779543Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2505433,
    events_root: None,
}
2023-01-27T01:19:42.779549Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 2
2023-01-27T01:19:42.779551Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeDynamicCode"::Berlin::2
2023-01-27T01:19:42.779553Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeDynamicCode.json"
2023-01-27T01:19:42.779556Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:42.779557Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:42.779715Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeDynamicCode"
2023-01-27T01:19:42.779719Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2505433,
    events_root: None,
}
2023-01-27T01:19:42.779725Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 3
2023-01-27T01:19:42.779728Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeDynamicCode"::Berlin::3
2023-01-27T01:19:42.779729Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeDynamicCode.json"
2023-01-27T01:19:42.779733Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:42.779734Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:42.779890Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeDynamicCode"
2023-01-27T01:19:42.779894Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2505433,
    events_root: None,
}
2023-01-27T01:19:42.779900Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:42.779903Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeDynamicCode"::London::0
2023-01-27T01:19:42.779904Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeDynamicCode.json"
2023-01-27T01:19:42.779907Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:42.779908Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:42.780067Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeDynamicCode"
2023-01-27T01:19:42.780071Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2505433,
    events_root: None,
}
2023-01-27T01:19:42.780077Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-27T01:19:42.780079Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeDynamicCode"::London::1
2023-01-27T01:19:42.780081Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeDynamicCode.json"
2023-01-27T01:19:42.780083Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:42.780085Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:42.780249Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeDynamicCode"
2023-01-27T01:19:42.780253Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2505433,
    events_root: None,
}
2023-01-27T01:19:42.780258Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 2
2023-01-27T01:19:42.780261Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeDynamicCode"::London::2
2023-01-27T01:19:42.780262Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeDynamicCode.json"
2023-01-27T01:19:42.780265Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:42.780266Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:42.780424Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeDynamicCode"
2023-01-27T01:19:42.780428Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2505433,
    events_root: None,
}
2023-01-27T01:19:42.780434Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 3
2023-01-27T01:19:42.780436Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeDynamicCode"::London::3
2023-01-27T01:19:42.780438Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeDynamicCode.json"
2023-01-27T01:19:42.780441Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:42.780442Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:42.780607Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeDynamicCode"
2023-01-27T01:19:42.780612Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2505433,
    events_root: None,
}
2023-01-27T01:19:42.780618Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:42.780621Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeDynamicCode"::Merge::0
2023-01-27T01:19:42.780624Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeDynamicCode.json"
2023-01-27T01:19:42.780628Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:42.780630Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:42.780838Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeDynamicCode"
2023-01-27T01:19:42.780844Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2505433,
    events_root: None,
}
2023-01-27T01:19:42.780851Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-27T01:19:42.780854Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeDynamicCode"::Merge::1
2023-01-27T01:19:42.780857Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeDynamicCode.json"
2023-01-27T01:19:42.780861Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:42.780863Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:42.781025Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeDynamicCode"
2023-01-27T01:19:42.781029Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2505433,
    events_root: None,
}
2023-01-27T01:19:42.781035Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 2
2023-01-27T01:19:42.781037Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeDynamicCode"::Merge::2
2023-01-27T01:19:42.781039Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeDynamicCode.json"
2023-01-27T01:19:42.781041Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:42.781042Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:42.781206Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeDynamicCode"
2023-01-27T01:19:42.781211Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2505433,
    events_root: None,
}
2023-01-27T01:19:42.781217Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 3
2023-01-27T01:19:42.781219Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeDynamicCode"::Merge::3
2023-01-27T01:19:42.781221Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeDynamicCode.json"
2023-01-27T01:19:42.781223Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:42.781224Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:42.781381Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeDynamicCode"
2023-01-27T01:19:42.781385Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2505433,
    events_root: None,
}
2023-01-27T01:19:42.783008Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:359.272084ms
2023-01-27T01:19:43.045626Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeDynamicCode2SelfCall.json", Total Files :: 1
2023-01-27T01:19:43.113944Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:43.114107Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:43.114112Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:43.114168Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:43.114170Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:43.114232Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:43.114234Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:43.114291Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:43.114368Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:43.114371Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeDynamicCode2SelfCall"::Istanbul::0
2023-01-27T01:19:43.114374Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeDynamicCode2SelfCall.json"
2023-01-27T01:19:43.114378Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:43.114380Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:43.464769Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeDynamicCode2SelfCall"
2023-01-27T01:19:43.464785Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2505433,
    events_root: None,
}
2023-01-27T01:19:43.464797Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-27T01:19:43.464801Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeDynamicCode2SelfCall"::Istanbul::1
2023-01-27T01:19:43.464803Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeDynamicCode2SelfCall.json"
2023-01-27T01:19:43.464806Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:43.464807Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:43.465037Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeDynamicCode2SelfCall"
2023-01-27T01:19:43.465043Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2505433,
    events_root: None,
}
2023-01-27T01:19:43.465051Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:43.465055Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeDynamicCode2SelfCall"::Berlin::0
2023-01-27T01:19:43.465058Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeDynamicCode2SelfCall.json"
2023-01-27T01:19:43.465062Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:43.465064Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:43.465235Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeDynamicCode2SelfCall"
2023-01-27T01:19:43.465241Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2505433,
    events_root: None,
}
2023-01-27T01:19:43.465247Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-27T01:19:43.465249Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeDynamicCode2SelfCall"::Berlin::1
2023-01-27T01:19:43.465251Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeDynamicCode2SelfCall.json"
2023-01-27T01:19:43.465254Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:43.465255Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:43.465424Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeDynamicCode2SelfCall"
2023-01-27T01:19:43.465429Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2505433,
    events_root: None,
}
2023-01-27T01:19:43.465435Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:43.465438Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeDynamicCode2SelfCall"::London::0
2023-01-27T01:19:43.465439Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeDynamicCode2SelfCall.json"
2023-01-27T01:19:43.465442Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:43.465444Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:43.465605Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeDynamicCode2SelfCall"
2023-01-27T01:19:43.465610Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2505433,
    events_root: None,
}
2023-01-27T01:19:43.465615Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-27T01:19:43.465618Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeDynamicCode2SelfCall"::London::1
2023-01-27T01:19:43.465619Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeDynamicCode2SelfCall.json"
2023-01-27T01:19:43.465622Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:43.465623Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:43.465784Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeDynamicCode2SelfCall"
2023-01-27T01:19:43.465790Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2505433,
    events_root: None,
}
2023-01-27T01:19:43.465795Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:43.465797Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeDynamicCode2SelfCall"::Merge::0
2023-01-27T01:19:43.465799Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeDynamicCode2SelfCall.json"
2023-01-27T01:19:43.465802Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:43.465803Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:43.465965Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeDynamicCode2SelfCall"
2023-01-27T01:19:43.465971Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2505433,
    events_root: None,
}
2023-01-27T01:19:43.465976Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-27T01:19:43.465979Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeDynamicCode2SelfCall"::Merge::1
2023-01-27T01:19:43.465980Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeDynamicCode2SelfCall.json"
2023-01-27T01:19:43.465983Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:43.465984Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:43.466146Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeDynamicCode2SelfCall"
2023-01-27T01:19:43.466151Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2505433,
    events_root: None,
}
2023-01-27T01:19:43.467617Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:352.220211ms
2023-01-27T01:19:43.723600Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeEmptycontract.json", Total Files :: 1
2023-01-27T01:19:43.755084Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:43.755276Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:43.755282Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:43.755360Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:43.755469Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:43.755474Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeEmptycontract"::Istanbul::0
2023-01-27T01:19:43.755478Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeEmptycontract.json"
2023-01-27T01:19:43.755481Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:43.755483Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:44.119430Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeEmptycontract"
2023-01-27T01:19:44.119446Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543487,
    events_root: None,
}
2023-01-27T01:19:44.119454Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:44.119469Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:44.119474Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeEmptycontract"::Berlin::0
2023-01-27T01:19:44.119476Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeEmptycontract.json"
2023-01-27T01:19:44.119479Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:44.119480Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:44.119606Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeEmptycontract"
2023-01-27T01:19:44.119610Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543487,
    events_root: None,
}
2023-01-27T01:19:44.119613Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:44.119622Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:44.119624Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeEmptycontract"::London::0
2023-01-27T01:19:44.119626Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeEmptycontract.json"
2023-01-27T01:19:44.119628Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:44.119629Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:44.119725Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeEmptycontract"
2023-01-27T01:19:44.119730Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543487,
    events_root: None,
}
2023-01-27T01:19:44.119733Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:44.119744Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:44.119746Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeEmptycontract"::Merge::0
2023-01-27T01:19:44.119748Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeEmptycontract.json"
2023-01-27T01:19:44.119752Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:44.119755Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:44.119851Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeEmptycontract"
2023-01-27T01:19:44.119855Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543487,
    events_root: None,
}
2023-01-27T01:19:44.119858Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:44.121447Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:364.787465ms
2023-01-27T01:19:44.401451Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeInInitcodeToEmptyContract.json", Total Files :: 1
2023-01-27T01:19:44.437814Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:44.437957Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:44.437960Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:44.438017Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:44.438019Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:44.438077Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:44.438079Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:44.438136Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:44.438215Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:44.438219Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeInInitcodeToEmptyContract"::Istanbul::0
2023-01-27T01:19:44.438224Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeInInitcodeToEmptyContract.json"
2023-01-27T01:19:44.438228Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:44.438229Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:44.808895Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeInInitcodeToEmptyContract"
2023-01-27T01:19:44.808912Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2005433,
    events_root: None,
}
2023-01-27T01:19:44.808927Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-27T01:19:44.808932Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeInInitcodeToEmptyContract"::Istanbul::1
2023-01-27T01:19:44.808934Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeInInitcodeToEmptyContract.json"
2023-01-27T01:19:44.808939Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:44.808941Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:44.809066Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeInInitcodeToEmptyContract"
2023-01-27T01:19:44.809071Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2005433,
    events_root: None,
}
2023-01-27T01:19:44.809080Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:44.809083Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeInInitcodeToEmptyContract"::Berlin::0
2023-01-27T01:19:44.809086Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeInInitcodeToEmptyContract.json"
2023-01-27T01:19:44.809090Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:44.809092Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:44.809205Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeInInitcodeToEmptyContract"
2023-01-27T01:19:44.809211Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2005433,
    events_root: None,
}
2023-01-27T01:19:44.809220Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-27T01:19:44.809222Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeInInitcodeToEmptyContract"::Berlin::1
2023-01-27T01:19:44.809225Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeInInitcodeToEmptyContract.json"
2023-01-27T01:19:44.809229Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:44.809231Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:44.809360Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeInInitcodeToEmptyContract"
2023-01-27T01:19:44.809365Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2005433,
    events_root: None,
}
2023-01-27T01:19:44.809373Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:44.809376Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeInInitcodeToEmptyContract"::London::0
2023-01-27T01:19:44.809379Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeInInitcodeToEmptyContract.json"
2023-01-27T01:19:44.809382Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:44.809384Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:44.809496Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeInInitcodeToEmptyContract"
2023-01-27T01:19:44.809501Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2005433,
    events_root: None,
}
2023-01-27T01:19:44.809509Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-27T01:19:44.809513Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeInInitcodeToEmptyContract"::London::1
2023-01-27T01:19:44.809516Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeInInitcodeToEmptyContract.json"
2023-01-27T01:19:44.809520Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:44.809522Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:44.809632Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeInInitcodeToEmptyContract"
2023-01-27T01:19:44.809638Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2005433,
    events_root: None,
}
2023-01-27T01:19:44.809646Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:44.809649Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeInInitcodeToEmptyContract"::Merge::0
2023-01-27T01:19:44.809651Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeInInitcodeToEmptyContract.json"
2023-01-27T01:19:44.809655Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:44.809657Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:44.809769Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeInInitcodeToEmptyContract"
2023-01-27T01:19:44.809774Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2005433,
    events_root: None,
}
2023-01-27T01:19:44.809782Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-27T01:19:44.809784Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeInInitcodeToEmptyContract"::Merge::1
2023-01-27T01:19:44.809787Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeInInitcodeToEmptyContract.json"
2023-01-27T01:19:44.809792Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:44.809794Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:44.809907Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeInInitcodeToEmptyContract"
2023-01-27T01:19:44.809912Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2005433,
    events_root: None,
}
2023-01-27T01:19:44.811432Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:372.110071ms
2023-01-27T01:19:45.080838Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeInInitcodeToExisContractWithVTransferNEMoney.json", Total Files :: 1
2023-01-27T01:19:45.138623Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:45.138798Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:45.138802Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:45.138857Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:45.138859Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:45.138919Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:45.138921Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:45.138978Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:45.138980Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:45.139032Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:45.139120Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:45.139124Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeInInitcodeToExisContractWithVTransferNEMoney"::Istanbul::0
2023-01-27T01:19:45.139127Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeInInitcodeToExisContractWithVTransferNEMoney.json"
2023-01-27T01:19:45.139130Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:45.139132Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:45.515793Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeInInitcodeToExisContractWithVTransferNEMoney"
2023-01-27T01:19:45.515807Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2005433,
    events_root: None,
}
2023-01-27T01:19:45.515817Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-27T01:19:45.515821Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeInInitcodeToExisContractWithVTransferNEMoney"::Istanbul::1
2023-01-27T01:19:45.515823Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeInInitcodeToExisContractWithVTransferNEMoney.json"
2023-01-27T01:19:45.515827Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:45.515828Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:45.515944Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeInInitcodeToExisContractWithVTransferNEMoney"
2023-01-27T01:19:45.515948Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2005433,
    events_root: None,
}
2023-01-27T01:19:45.515954Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:45.515956Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeInInitcodeToExisContractWithVTransferNEMoney"::Berlin::0
2023-01-27T01:19:45.515958Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeInInitcodeToExisContractWithVTransferNEMoney.json"
2023-01-27T01:19:45.515961Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:45.515962Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:45.516064Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeInInitcodeToExisContractWithVTransferNEMoney"
2023-01-27T01:19:45.516068Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2005433,
    events_root: None,
}
2023-01-27T01:19:45.516073Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-27T01:19:45.516075Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeInInitcodeToExisContractWithVTransferNEMoney"::Berlin::1
2023-01-27T01:19:45.516077Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeInInitcodeToExisContractWithVTransferNEMoney.json"
2023-01-27T01:19:45.516080Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:45.516081Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:45.516200Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeInInitcodeToExisContractWithVTransferNEMoney"
2023-01-27T01:19:45.516204Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2005433,
    events_root: None,
}
2023-01-27T01:19:45.516209Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:45.516211Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeInInitcodeToExisContractWithVTransferNEMoney"::London::0
2023-01-27T01:19:45.516213Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeInInitcodeToExisContractWithVTransferNEMoney.json"
2023-01-27T01:19:45.516216Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:45.516217Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:45.516320Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeInInitcodeToExisContractWithVTransferNEMoney"
2023-01-27T01:19:45.516324Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2005433,
    events_root: None,
}
2023-01-27T01:19:45.516330Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-27T01:19:45.516332Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeInInitcodeToExisContractWithVTransferNEMoney"::London::1
2023-01-27T01:19:45.516335Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeInInitcodeToExisContractWithVTransferNEMoney.json"
2023-01-27T01:19:45.516339Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:45.516340Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:45.516443Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeInInitcodeToExisContractWithVTransferNEMoney"
2023-01-27T01:19:45.516448Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2005433,
    events_root: None,
}
2023-01-27T01:19:45.516452Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:45.516454Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeInInitcodeToExisContractWithVTransferNEMoney"::Merge::0
2023-01-27T01:19:45.516456Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeInInitcodeToExisContractWithVTransferNEMoney.json"
2023-01-27T01:19:45.516459Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:45.516460Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:45.516574Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeInInitcodeToExisContractWithVTransferNEMoney"
2023-01-27T01:19:45.516579Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2005433,
    events_root: None,
}
2023-01-27T01:19:45.516584Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-27T01:19:45.516586Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeInInitcodeToExisContractWithVTransferNEMoney"::Merge::1
2023-01-27T01:19:45.516588Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeInInitcodeToExisContractWithVTransferNEMoney.json"
2023-01-27T01:19:45.516591Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:45.516592Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:45.516695Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeInInitcodeToExisContractWithVTransferNEMoney"
2023-01-27T01:19:45.516699Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2005433,
    events_root: None,
}
2023-01-27T01:19:45.518103Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:378.088343ms
2023-01-27T01:19:45.797699Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeInInitcodeToExistingContract.json", Total Files :: 1
2023-01-27T01:19:45.859167Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:45.859311Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:45.859315Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:45.859368Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:45.859371Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:45.859432Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:45.859435Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:45.859489Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:45.859491Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:45.859545Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:45.859623Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:45.859627Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeInInitcodeToExistingContract"::Istanbul::0
2023-01-27T01:19:45.859630Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeInInitcodeToExistingContract.json"
2023-01-27T01:19:45.859634Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:45.859635Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:46.250035Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeInInitcodeToExistingContract"
2023-01-27T01:19:46.250051Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2005433,
    events_root: None,
}
2023-01-27T01:19:46.250062Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-27T01:19:46.250065Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeInInitcodeToExistingContract"::Istanbul::1
2023-01-27T01:19:46.250067Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeInInitcodeToExistingContract.json"
2023-01-27T01:19:46.250070Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:46.250072Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:46.250189Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeInInitcodeToExistingContract"
2023-01-27T01:19:46.250195Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2005433,
    events_root: None,
}
2023-01-27T01:19:46.250200Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:46.250202Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeInInitcodeToExistingContract"::Berlin::0
2023-01-27T01:19:46.250204Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeInInitcodeToExistingContract.json"
2023-01-27T01:19:46.250207Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:46.250208Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:46.250313Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeInInitcodeToExistingContract"
2023-01-27T01:19:46.250317Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2005433,
    events_root: None,
}
2023-01-27T01:19:46.250322Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-27T01:19:46.250324Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeInInitcodeToExistingContract"::Berlin::1
2023-01-27T01:19:46.250327Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeInInitcodeToExistingContract.json"
2023-01-27T01:19:46.250330Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:46.250331Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:46.250454Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeInInitcodeToExistingContract"
2023-01-27T01:19:46.250458Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2005433,
    events_root: None,
}
2023-01-27T01:19:46.250463Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:46.250465Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeInInitcodeToExistingContract"::London::0
2023-01-27T01:19:46.250467Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeInInitcodeToExistingContract.json"
2023-01-27T01:19:46.250470Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:46.250471Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:46.250573Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeInInitcodeToExistingContract"
2023-01-27T01:19:46.250578Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2005433,
    events_root: None,
}
2023-01-27T01:19:46.250584Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-27T01:19:46.250586Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeInInitcodeToExistingContract"::London::1
2023-01-27T01:19:46.250588Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeInInitcodeToExistingContract.json"
2023-01-27T01:19:46.250591Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:46.250592Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:46.250695Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeInInitcodeToExistingContract"
2023-01-27T01:19:46.250699Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2005433,
    events_root: None,
}
2023-01-27T01:19:46.250704Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:46.250707Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeInInitcodeToExistingContract"::Merge::0
2023-01-27T01:19:46.250708Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeInInitcodeToExistingContract.json"
2023-01-27T01:19:46.250711Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:46.250712Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:46.250813Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeInInitcodeToExistingContract"
2023-01-27T01:19:46.250817Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2005433,
    events_root: None,
}
2023-01-27T01:19:46.250822Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-27T01:19:46.250824Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeInInitcodeToExistingContract"::Merge::1
2023-01-27T01:19:46.250826Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeInInitcodeToExistingContract.json"
2023-01-27T01:19:46.250829Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-27T01:19:46.250830Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:46.250931Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeInInitcodeToExistingContract"
2023-01-27T01:19:46.250934Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2005433,
    events_root: None,
}
2023-01-27T01:19:46.252554Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:391.777458ms
2023-01-27T01:19:46.529735Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeInInitcodeToExistingContractWithValueTransfer.json", Total Files :: 1
2023-01-27T01:19:46.562880Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:46.563020Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:46.563024Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:46.563078Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:46.563080Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:46.563141Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:46.563226Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:46.563229Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeInInitcodeToExistingContractWithValueTransfer"::Istanbul::0
2023-01-27T01:19:46.563232Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeInInitcodeToExistingContractWithValueTransfer.json"
2023-01-27T01:19:46.563236Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:46.563237Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [19, 19, 96, 8, 182, 79, 245, 146, 129, 155, 47, 166, 212, 63, 40, 53, 196, 82, 2, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-27T01:19:47.199048Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeInInitcodeToExistingContractWithValueTransfer"
2023-01-27T01:19:47.199059Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12221081,
    events_root: None,
}
2023-01-27T01:19:47.199078Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:47.199082Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeInInitcodeToExistingContractWithValueTransfer"::Berlin::0
2023-01-27T01:19:47.199085Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeInInitcodeToExistingContractWithValueTransfer.json"
2023-01-27T01:19:47.199088Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:47.199090Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [124, 90, 44, 145, 178, 45, 122, 146, 38, 82, 61, 75, 167, 23, 219, 106, 251, 116, 30, 189, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-01-27T01:19:47.199724Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeInInitcodeToExistingContractWithValueTransfer"
2023-01-27T01:19:47.199729Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12635641,
    events_root: None,
}
2023-01-27T01:19:47.199740Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:47.199742Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeInInitcodeToExistingContractWithValueTransfer"::London::0
2023-01-27T01:19:47.199745Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeInInitcodeToExistingContractWithValueTransfer.json"
2023-01-27T01:19:47.199748Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:47.199749Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [85, 225, 180, 184, 198, 80, 147, 57, 204, 233, 99, 201, 185, 164, 106, 230, 220, 29, 81, 93, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-01-27T01:19:47.200261Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeInInitcodeToExistingContractWithValueTransfer"
2023-01-27T01:19:47.200266Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12265435,
    events_root: None,
}
2023-01-27T01:19:47.200276Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:47.200279Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeInInitcodeToExistingContractWithValueTransfer"::Merge::0
2023-01-27T01:19:47.200281Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodeInInitcodeToExistingContractWithValueTransfer.json"
2023-01-27T01:19:47.200284Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:47.200285Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [119, 32, 219, 74, 113, 179, 136, 255, 7, 69, 60, 90, 226, 153, 143, 86, 21, 251, 52, 236, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-01-27T01:19:47.200825Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeInInitcodeToExistingContractWithValueTransfer"
2023-01-27T01:19:47.200831Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12705662,
    events_root: None,
}
2023-01-27T01:19:47.202769Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:637.966356ms
2023-01-27T01:19:47.481049Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcode_checkPC.json", Total Files :: 1
2023-01-27T01:19:47.516075Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:47.516215Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:47.516219Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:47.516273Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:47.516275Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:47.516338Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:47.516415Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:47.516418Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcode_checkPC"::Istanbul::0
2023-01-27T01:19:47.516421Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcode_checkPC.json"
2023-01-27T01:19:47.516424Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:47.516426Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:47.872548Z  INFO evm_eth_compliance::statetest::runner: UC : "callcode_checkPC"
2023-01-27T01:19:47.872563Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3653861,
    events_root: None,
}
2023-01-27T01:19:47.872575Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:47.872579Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcode_checkPC"::Berlin::0
2023-01-27T01:19:47.872580Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcode_checkPC.json"
2023-01-27T01:19:47.872583Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:47.872585Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:47.872774Z  INFO evm_eth_compliance::statetest::runner: UC : "callcode_checkPC"
2023-01-27T01:19:47.872779Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2753255,
    events_root: None,
}
2023-01-27T01:19:47.872786Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:47.872788Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcode_checkPC"::London::0
2023-01-27T01:19:47.872790Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcode_checkPC.json"
2023-01-27T01:19:47.872792Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:47.872793Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:47.872959Z  INFO evm_eth_compliance::statetest::runner: UC : "callcode_checkPC"
2023-01-27T01:19:47.872964Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2753255,
    events_root: None,
}
2023-01-27T01:19:47.872970Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:47.872972Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcode_checkPC"::Merge::0
2023-01-27T01:19:47.872974Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcode_checkPC.json"
2023-01-27T01:19:47.872976Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:47.872978Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:47.873141Z  INFO evm_eth_compliance::statetest::runner: UC : "callcode_checkPC"
2023-01-27T01:19:47.873148Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2753255,
    events_root: None,
}
2023-01-27T01:19:47.874821Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:357.083553ms
2023-01-27T01:19:48.151086Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecall_10.json", Total Files :: 1
2023-01-27T01:19:48.212190Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:48.212332Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:48.212335Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:48.212388Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:48.212391Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:48.212448Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:48.212451Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:48.212508Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:48.212596Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:48.212600Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10"::Istanbul::0
2023-01-27T01:19:48.212603Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecall_10.json"
2023-01-27T01:19:48.212606Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:48.212608Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:48.583546Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecall_10"
2023-01-27T01:19:48.583566Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:48.583574Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:48.583592Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:48.583599Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10"::Berlin::0
2023-01-27T01:19:48.583601Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecall_10.json"
2023-01-27T01:19:48.583605Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:48.583606Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:48.583739Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecall_10"
2023-01-27T01:19:48.583744Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:48.583748Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:48.583759Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:48.583762Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10"::London::0
2023-01-27T01:19:48.583764Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecall_10.json"
2023-01-27T01:19:48.583768Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:48.583769Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:48.583882Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecall_10"
2023-01-27T01:19:48.583886Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:48.583890Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:48.583901Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:48.583903Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10"::Merge::0
2023-01-27T01:19:48.583906Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecall_10.json"
2023-01-27T01:19:48.583909Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:48.583911Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:48.584007Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecall_10"
2023-01-27T01:19:48.584011Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:48.584014Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:48.585691Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:371.838289ms
2023-01-27T01:19:48.866429Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecall_10_OOGE.json", Total Files :: 1
2023-01-27T01:19:48.901925Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:48.902064Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:48.902070Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:48.902123Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:48.902125Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:48.902183Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:48.902185Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:48.902242Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:48.902316Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:48.902319Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10_OOGE"::Istanbul::0
2023-01-27T01:19:48.902322Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecall_10_OOGE.json"
2023-01-27T01:19:48.902325Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:48.902326Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:49.356413Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecall_10_OOGE"
2023-01-27T01:19:49.356428Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:49.356435Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:49.356449Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:49.356454Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10_OOGE"::Berlin::0
2023-01-27T01:19:49.356456Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecall_10_OOGE.json"
2023-01-27T01:19:49.356458Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:49.356460Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:49.356579Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecall_10_OOGE"
2023-01-27T01:19:49.356586Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:49.356589Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:49.356597Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:49.356599Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10_OOGE"::London::0
2023-01-27T01:19:49.356602Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecall_10_OOGE.json"
2023-01-27T01:19:49.356604Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:49.356606Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:49.356695Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecall_10_OOGE"
2023-01-27T01:19:49.356700Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:49.356703Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:49.356711Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:49.356713Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10_OOGE"::Merge::0
2023-01-27T01:19:49.356715Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecall_10_OOGE.json"
2023-01-27T01:19:49.356717Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:49.356719Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:49.356804Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecall_10_OOGE"
2023-01-27T01:19:49.356807Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:49.356810Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:49.358386Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:454.899493ms
2023-01-27T01:19:49.656331Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecall_10_SuicideEnd.json", Total Files :: 1
2023-01-27T01:19:49.695628Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:49.695762Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:49.695765Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:49.695815Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:49.695817Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:49.695873Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:49.695875Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:49.695928Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:49.696001Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:49.696004Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10_SuicideEnd"::Istanbul::0
2023-01-27T01:19:49.696007Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecall_10_SuicideEnd.json"
2023-01-27T01:19:49.696010Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:49.696012Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:50.037758Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecall_10_SuicideEnd"
2023-01-27T01:19:50.037775Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:50.037782Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:50.037795Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:50.037800Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10_SuicideEnd"::Berlin::0
2023-01-27T01:19:50.037801Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecall_10_SuicideEnd.json"
2023-01-27T01:19:50.037804Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:50.037805Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:50.037922Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecall_10_SuicideEnd"
2023-01-27T01:19:50.037928Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:50.037930Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:50.037940Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:50.037942Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10_SuicideEnd"::London::0
2023-01-27T01:19:50.037945Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecall_10_SuicideEnd.json"
2023-01-27T01:19:50.037948Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:50.037950Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:50.038050Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecall_10_SuicideEnd"
2023-01-27T01:19:50.038069Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:50.038073Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:50.038084Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:50.038087Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10_SuicideEnd"::Merge::0
2023-01-27T01:19:50.038089Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecall_10_SuicideEnd.json"
2023-01-27T01:19:50.038093Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:50.038095Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:50.038191Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecall_10_SuicideEnd"
2023-01-27T01:19:50.038195Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:50.038198Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:50.039718Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:342.587002ms
2023-01-27T01:19:50.300423Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcall_100.json", Total Files :: 1
2023-01-27T01:19:50.333132Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:50.333279Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:50.333284Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:50.333337Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:50.333340Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:50.333400Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:50.333403Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:50.333461Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:50.333463Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:50.333517Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:50.333594Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:50.333597Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100"::Istanbul::0
2023-01-27T01:19:50.333599Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcall_100.json"
2023-01-27T01:19:50.333603Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:50.333604Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:50.692673Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100"
2023-01-27T01:19:50.692688Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:50.692694Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:50.692707Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:50.692711Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100"::Berlin::0
2023-01-27T01:19:50.692713Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcall_100.json"
2023-01-27T01:19:50.692715Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:50.692717Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:50.692827Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100"
2023-01-27T01:19:50.692832Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:50.692836Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:50.692849Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:50.692852Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100"::London::0
2023-01-27T01:19:50.692854Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcall_100.json"
2023-01-27T01:19:50.692857Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:50.692859Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:50.692969Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100"
2023-01-27T01:19:50.692974Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:50.692977Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:50.692988Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:50.692990Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100"::Merge::0
2023-01-27T01:19:50.692993Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcall_100.json"
2023-01-27T01:19:50.692996Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:50.692998Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:50.693095Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100"
2023-01-27T01:19:50.693100Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:50.693103Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:50.695088Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:359.985281ms
2023-01-27T01:19:50.949816Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcall_100_OOGE.json", Total Files :: 1
2023-01-27T01:19:50.991533Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:50.991681Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:50.991685Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:50.991738Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:50.991741Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:50.991800Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:50.991802Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:50.991860Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:50.991862Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:50.991917Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:50.991996Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:50.991999Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_OOGE"::Istanbul::0
2023-01-27T01:19:50.992001Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcall_100_OOGE.json"
2023-01-27T01:19:50.992005Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:50.992006Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:51.365779Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_OOGE"
2023-01-27T01:19:51.365792Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:51.365798Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:51.365812Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:51.365816Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_OOGE"::Berlin::0
2023-01-27T01:19:51.365818Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcall_100_OOGE.json"
2023-01-27T01:19:51.365820Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:51.365822Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:51.365939Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_OOGE"
2023-01-27T01:19:51.365944Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:51.365948Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:51.365960Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:51.365963Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_OOGE"::London::0
2023-01-27T01:19:51.365965Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcall_100_OOGE.json"
2023-01-27T01:19:51.365968Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:51.365969Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:51.366074Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_OOGE"
2023-01-27T01:19:51.366079Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:51.366083Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:51.366094Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:51.366097Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_OOGE"::Merge::0
2023-01-27T01:19:51.366099Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcall_100_OOGE.json"
2023-01-27T01:19:51.366102Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:51.366104Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:51.366200Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_OOGE"
2023-01-27T01:19:51.366205Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:51.366208Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:51.367653Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:374.689024ms
2023-01-27T01:19:51.633010Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcall_100_OOGMAfter.json", Total Files :: 1
2023-01-27T01:19:51.675885Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:51.676020Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:51.676024Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:51.676074Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:51.676076Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:51.676133Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:51.676135Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:51.676190Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:51.676192Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:51.676242Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:51.676315Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:51.676318Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_OOGMAfter"::Istanbul::0
2023-01-27T01:19:51.676320Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcall_100_OOGMAfter.json"
2023-01-27T01:19:51.676324Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:51.676325Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:52.034896Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_OOGMAfter"
2023-01-27T01:19:52.034909Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544011,
    events_root: None,
}
2023-01-27T01:19:52.034915Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:52.034929Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:52.034933Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_OOGMAfter"::Berlin::0
2023-01-27T01:19:52.034935Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcall_100_OOGMAfter.json"
2023-01-27T01:19:52.034938Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:52.034939Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:52.035046Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_OOGMAfter"
2023-01-27T01:19:52.035052Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544011,
    events_root: None,
}
2023-01-27T01:19:52.035055Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:52.035063Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:52.035065Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_OOGMAfter"::London::0
2023-01-27T01:19:52.035067Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcall_100_OOGMAfter.json"
2023-01-27T01:19:52.035070Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:52.035072Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:52.035180Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_OOGMAfter"
2023-01-27T01:19:52.035185Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544011,
    events_root: None,
}
2023-01-27T01:19:52.035189Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:52.035200Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:52.035202Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_OOGMAfter"::Merge::0
2023-01-27T01:19:52.035205Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcall_100_OOGMAfter.json"
2023-01-27T01:19:52.035208Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:52.035210Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:52.035319Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_OOGMAfter"
2023-01-27T01:19:52.035323Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544011,
    events_root: None,
}
2023-01-27T01:19:52.035327Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:52.036937Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:359.455587ms
2023-01-27T01:19:52.315992Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcall_100_OOGMBefore.json", Total Files :: 1
2023-01-27T01:19:52.347246Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:52.347387Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:52.347392Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:52.347447Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:52.347450Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:52.347510Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:52.347512Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:52.347569Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:52.347572Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:52.347625Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:52.347703Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:52.347708Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_OOGMBefore"::Istanbul::0
2023-01-27T01:19:52.347711Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcall_100_OOGMBefore.json"
2023-01-27T01:19:52.347714Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:52.347715Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:52.728806Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_OOGMBefore"
2023-01-27T01:19:52.728824Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:52.728833Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:52.728849Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:52.728854Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_OOGMBefore"::Berlin::0
2023-01-27T01:19:52.728856Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcall_100_OOGMBefore.json"
2023-01-27T01:19:52.728859Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:52.728861Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:52.729028Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_OOGMBefore"
2023-01-27T01:19:52.729033Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:52.729038Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:52.729050Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:52.729053Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_OOGMBefore"::London::0
2023-01-27T01:19:52.729056Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcall_100_OOGMBefore.json"
2023-01-27T01:19:52.729059Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:52.729061Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:52.729161Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_OOGMBefore"
2023-01-27T01:19:52.729165Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:52.729168Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:52.729176Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:52.729178Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_OOGMBefore"::Merge::0
2023-01-27T01:19:52.729180Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcall_100_OOGMBefore.json"
2023-01-27T01:19:52.729183Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:52.729184Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:52.729274Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_OOGMBefore"
2023-01-27T01:19:52.729278Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:52.729280Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:52.731072Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:382.048962ms
2023-01-27T01:19:53.016728Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcall_100_SuicideEnd.json", Total Files :: 1
2023-01-27T01:19:53.069923Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:53.070054Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:53.070058Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:53.070109Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:53.070111Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:53.070168Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:53.070170Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:53.070223Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:53.070225Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:53.070275Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:53.070348Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:53.070351Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_SuicideEnd"::Istanbul::0
2023-01-27T01:19:53.070354Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcall_100_SuicideEnd.json"
2023-01-27T01:19:53.070357Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:53.070358Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:53.412101Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_SuicideEnd"
2023-01-27T01:19:53.412120Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:53.412127Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:53.412140Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:53.412145Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_SuicideEnd"::Berlin::0
2023-01-27T01:19:53.412146Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcall_100_SuicideEnd.json"
2023-01-27T01:19:53.412149Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:53.412151Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:53.412305Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_SuicideEnd"
2023-01-27T01:19:53.412310Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:53.412314Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:53.412325Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:53.412328Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_SuicideEnd"::London::0
2023-01-27T01:19:53.412330Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcall_100_SuicideEnd.json"
2023-01-27T01:19:53.412334Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:53.412335Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:53.412430Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_SuicideEnd"
2023-01-27T01:19:53.412434Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:53.412437Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:53.412445Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:53.412447Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_SuicideEnd"::Merge::0
2023-01-27T01:19:53.412449Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcall_100_SuicideEnd.json"
2023-01-27T01:19:53.412451Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:53.412453Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:53.412550Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_SuicideEnd"
2023-01-27T01:19:53.412554Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:53.412557Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:53.413977Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:342.647147ms
2023-01-27T01:19:53.673306Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcall_100_SuicideMiddle.json", Total Files :: 1
2023-01-27T01:19:53.705323Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:53.705463Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:53.705467Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:53.705521Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:53.705523Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:53.705585Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:53.705587Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:53.705644Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:53.705646Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:53.705700Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:53.705779Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:53.705782Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_SuicideMiddle"::Istanbul::0
2023-01-27T01:19:53.705785Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcall_100_SuicideMiddle.json"
2023-01-27T01:19:53.705789Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:53.705790Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:54.068990Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_SuicideMiddle"
2023-01-27T01:19:54.069006Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:54.069014Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:54.069028Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:54.069032Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_SuicideMiddle"::Berlin::0
2023-01-27T01:19:54.069034Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcall_100_SuicideMiddle.json"
2023-01-27T01:19:54.069037Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:54.069039Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:54.069145Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_SuicideMiddle"
2023-01-27T01:19:54.069150Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:54.069152Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:54.069162Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:54.069164Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_SuicideMiddle"::London::0
2023-01-27T01:19:54.069167Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcall_100_SuicideMiddle.json"
2023-01-27T01:19:54.069169Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:54.069171Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:54.069262Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_SuicideMiddle"
2023-01-27T01:19:54.069266Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:54.069269Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:54.069277Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:54.069279Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_SuicideMiddle"::Merge::0
2023-01-27T01:19:54.069281Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcall_100_SuicideMiddle.json"
2023-01-27T01:19:54.069284Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:54.069285Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:54.069375Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_SuicideMiddle"
2023-01-27T01:19:54.069380Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:54.069384Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:54.071136Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:364.074512ms
2023-01-27T01:19:54.344833Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcall_ABCB_RECURSIVE.json", Total Files :: 1
2023-01-27T01:19:54.401170Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:54.401309Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:54.401313Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:54.401364Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:54.401366Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:54.401424Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:54.401426Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:54.401480Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:54.401554Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:54.401557Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_ABCB_RECURSIVE"::Istanbul::0
2023-01-27T01:19:54.401560Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcall_ABCB_RECURSIVE.json"
2023-01-27T01:19:54.401563Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:54.401565Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:54.742430Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_ABCB_RECURSIVE"
2023-01-27T01:19:54.742445Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543546,
    events_root: None,
}
2023-01-27T01:19:54.742451Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=36): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:54.742464Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:54.742469Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_ABCB_RECURSIVE"::Berlin::0
2023-01-27T01:19:54.742471Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcall_ABCB_RECURSIVE.json"
2023-01-27T01:19:54.742473Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:54.742476Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:54.742583Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_ABCB_RECURSIVE"
2023-01-27T01:19:54.742588Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543546,
    events_root: None,
}
2023-01-27T01:19:54.742591Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=36): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:54.742600Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:54.742602Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_ABCB_RECURSIVE"::London::0
2023-01-27T01:19:54.742604Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcall_ABCB_RECURSIVE.json"
2023-01-27T01:19:54.742607Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:54.742608Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:54.742696Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_ABCB_RECURSIVE"
2023-01-27T01:19:54.742700Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543546,
    events_root: None,
}
2023-01-27T01:19:54.742703Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=36): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:54.742713Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:54.742716Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_ABCB_RECURSIVE"::Merge::0
2023-01-27T01:19:54.742719Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcall_ABCB_RECURSIVE.json"
2023-01-27T01:19:54.742722Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:54.742723Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:54.742811Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_ABCB_RECURSIVE"
2023-01-27T01:19:54.742814Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543546,
    events_root: None,
}
2023-01-27T01:19:54.742817Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=36): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:54.744289Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:341.661222ms
2023-01-27T01:19:55.024448Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcallcode_101.json", Total Files :: 1
2023-01-27T01:19:55.055464Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:55.055602Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:55.055606Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:55.055658Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:55.055660Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:55.055718Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:55.055720Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:55.055776Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:55.055778Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:55.055830Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:55.055905Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:55.055908Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101"::Istanbul::0
2023-01-27T01:19:55.055911Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcallcode_101.json"
2023-01-27T01:19:55.055914Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:55.055916Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:55.410680Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101"
2023-01-27T01:19:55.410694Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:55.410700Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:55.410713Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:55.410717Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101"::Berlin::0
2023-01-27T01:19:55.410719Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcallcode_101.json"
2023-01-27T01:19:55.410721Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:55.410723Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:55.410837Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101"
2023-01-27T01:19:55.410841Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:55.410844Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:55.410852Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:55.410854Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101"::London::0
2023-01-27T01:19:55.410856Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcallcode_101.json"
2023-01-27T01:19:55.410859Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:55.410860Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:55.410943Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101"
2023-01-27T01:19:55.410947Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:55.410950Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:55.410958Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:55.410960Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101"::Merge::0
2023-01-27T01:19:55.410962Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcallcode_101.json"
2023-01-27T01:19:55.410965Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:55.410966Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:55.411048Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101"
2023-01-27T01:19:55.411052Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:55.411054Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:55.412475Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:355.603519ms
2023-01-27T01:19:55.689777Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcallcode_101_OOGE.json", Total Files :: 1
2023-01-27T01:19:55.720776Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:55.720948Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:55.720955Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:55.721027Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:55.721031Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:55.721096Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:55.721099Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:55.721163Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:55.721166Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:55.721219Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:55.721297Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:55.721301Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_OOGE"::Istanbul::0
2023-01-27T01:19:55.721303Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcallcode_101_OOGE.json"
2023-01-27T01:19:55.721307Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:55.721309Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:56.131499Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_OOGE"
2023-01-27T01:19:56.131516Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:56.131523Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:56.131541Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:56.131547Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_OOGE"::Berlin::0
2023-01-27T01:19:56.131549Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcallcode_101_OOGE.json"
2023-01-27T01:19:56.131552Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:56.131554Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:56.131690Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_OOGE"
2023-01-27T01:19:56.131696Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:56.131700Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:56.131714Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:56.131716Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_OOGE"::London::0
2023-01-27T01:19:56.131719Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcallcode_101_OOGE.json"
2023-01-27T01:19:56.131723Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:56.131725Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:56.131835Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_OOGE"
2023-01-27T01:19:56.131840Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:56.131844Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:56.131856Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:56.131859Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_OOGE"::Merge::0
2023-01-27T01:19:56.131861Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcallcode_101_OOGE.json"
2023-01-27T01:19:56.131865Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:56.131867Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:56.131977Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_OOGE"
2023-01-27T01:19:56.131982Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:56.131985Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:56.133872Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:411.226622ms
2023-01-27T01:19:56.404784Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcallcode_101_OOGMAfter.json", Total Files :: 1
2023-01-27T01:19:56.435048Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:56.435185Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:56.435188Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:56.435239Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:56.435241Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:56.435297Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:56.435299Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:56.435354Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:56.435356Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:56.435408Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:56.435483Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:56.435486Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_OOGMAfter"::Istanbul::0
2023-01-27T01:19:56.435489Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcallcode_101_OOGMAfter.json"
2023-01-27T01:19:56.435492Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:56.435494Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:56.778413Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_OOGMAfter"
2023-01-27T01:19:56.778428Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544011,
    events_root: None,
}
2023-01-27T01:19:56.778436Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:56.778450Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:56.778456Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_OOGMAfter"::Berlin::0
2023-01-27T01:19:56.778458Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcallcode_101_OOGMAfter.json"
2023-01-27T01:19:56.778462Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:56.778464Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:56.778576Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_OOGMAfter"
2023-01-27T01:19:56.778581Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544011,
    events_root: None,
}
2023-01-27T01:19:56.778585Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:56.778597Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:56.778600Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_OOGMAfter"::London::0
2023-01-27T01:19:56.778603Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcallcode_101_OOGMAfter.json"
2023-01-27T01:19:56.778607Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:56.778608Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:56.778700Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_OOGMAfter"
2023-01-27T01:19:56.778705Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544011,
    events_root: None,
}
2023-01-27T01:19:56.778708Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:56.778720Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:56.778723Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_OOGMAfter"::Merge::0
2023-01-27T01:19:56.778725Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcallcode_101_OOGMAfter.json"
2023-01-27T01:19:56.778729Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:56.778731Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:56.778823Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_OOGMAfter"
2023-01-27T01:19:56.778827Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544011,
    events_root: None,
}
2023-01-27T01:19:56.778831Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:56.780165Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:343.800014ms
2023-01-27T01:19:57.054275Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcallcode_101_OOGMBefore.json", Total Files :: 1
2023-01-27T01:19:57.100980Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:57.101118Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:57.101122Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:57.101174Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:57.101176Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:57.101235Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:57.101237Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:57.101294Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:57.101297Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:57.101365Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:57.101443Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:57.101446Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_OOGMBefore"::Istanbul::0
2023-01-27T01:19:57.101449Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcallcode_101_OOGMBefore.json"
2023-01-27T01:19:57.101453Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:57.101454Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:57.449475Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_OOGMBefore"
2023-01-27T01:19:57.449489Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:57.449497Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:57.449510Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:57.449514Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_OOGMBefore"::Berlin::0
2023-01-27T01:19:57.449518Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcallcode_101_OOGMBefore.json"
2023-01-27T01:19:57.449522Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:57.449524Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:57.449627Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_OOGMBefore"
2023-01-27T01:19:57.449631Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:57.449634Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:57.449644Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:57.449646Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_OOGMBefore"::London::0
2023-01-27T01:19:57.449648Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcallcode_101_OOGMBefore.json"
2023-01-27T01:19:57.449651Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:57.449652Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:57.449741Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_OOGMBefore"
2023-01-27T01:19:57.449745Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:57.449748Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:57.449757Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:57.449759Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_OOGMBefore"::Merge::0
2023-01-27T01:19:57.449761Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcallcode_101_OOGMBefore.json"
2023-01-27T01:19:57.449764Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:57.449766Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:57.449857Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_OOGMBefore"
2023-01-27T01:19:57.449861Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:57.449864Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:57.451345Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:348.896792ms
2023-01-27T01:19:57.714691Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcallcode_101_SuicideEnd.json", Total Files :: 1
2023-01-27T01:19:57.780873Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:57.781014Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:57.781018Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:57.781072Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:57.781074Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:57.781135Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:57.781138Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:57.781194Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:57.781197Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:57.781256Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:57.781333Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:57.781336Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_SuicideEnd"::Istanbul::0
2023-01-27T01:19:57.781340Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcallcode_101_SuicideEnd.json"
2023-01-27T01:19:57.781344Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:57.781345Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:58.165093Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_SuicideEnd"
2023-01-27T01:19:58.165108Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:58.165115Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:58.165130Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:58.165134Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_SuicideEnd"::Berlin::0
2023-01-27T01:19:58.165137Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcallcode_101_SuicideEnd.json"
2023-01-27T01:19:58.165140Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:58.165143Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:58.165251Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_SuicideEnd"
2023-01-27T01:19:58.165256Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:58.165259Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:58.165268Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:58.165270Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_SuicideEnd"::London::0
2023-01-27T01:19:58.165272Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcallcode_101_SuicideEnd.json"
2023-01-27T01:19:58.165274Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:58.165275Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:58.165366Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_SuicideEnd"
2023-01-27T01:19:58.165371Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:58.165374Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:58.165382Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:58.165384Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_SuicideEnd"::Merge::0
2023-01-27T01:19:58.165386Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcallcode_101_SuicideEnd.json"
2023-01-27T01:19:58.165388Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:58.165390Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:58.165477Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_SuicideEnd"
2023-01-27T01:19:58.165481Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:58.165484Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:58.167153Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:384.625056ms
2023-01-27T01:19:58.423384Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcallcode_101_SuicideMiddle.json", Total Files :: 1
2023-01-27T01:19:58.458743Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:58.458886Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:58.458890Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:58.458944Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:58.458946Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:58.459007Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:58.459009Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:58.459066Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:58.459069Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:19:58.459122Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:58.459200Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:58.459203Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_SuicideMiddle"::Istanbul::0
2023-01-27T01:19:58.459206Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcallcode_101_SuicideMiddle.json"
2023-01-27T01:19:58.459209Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:58.459211Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:58.843570Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_SuicideMiddle"
2023-01-27T01:19:58.843587Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:58.843594Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:58.843608Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:58.843612Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_SuicideMiddle"::Berlin::0
2023-01-27T01:19:58.843614Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcallcode_101_SuicideMiddle.json"
2023-01-27T01:19:58.843617Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:58.843619Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:58.843736Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_SuicideMiddle"
2023-01-27T01:19:58.843741Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:58.843744Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:58.843754Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:58.843756Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_SuicideMiddle"::London::0
2023-01-27T01:19:58.843758Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcallcode_101_SuicideMiddle.json"
2023-01-27T01:19:58.843761Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:58.843762Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:58.843850Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_SuicideMiddle"
2023-01-27T01:19:58.843854Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:58.843857Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:58.843865Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:58.843868Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_SuicideMiddle"::Merge::0
2023-01-27T01:19:58.843870Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcallcode_101_SuicideMiddle.json"
2023-01-27T01:19:58.843873Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:58.843874Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:58.843961Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_SuicideMiddle"
2023-01-27T01:19:58.843965Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:19:58.843968Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:58.845410Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:385.238857ms
2023-01-27T01:19:59.126287Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcallcode_ABCB_RECURSIVE.json", Total Files :: 1
2023-01-27T01:19:59.175707Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:59.175843Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:59.175847Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:59.175900Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:59.175902Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:59.175961Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:59.175964Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:59.176023Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:59.176100Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:59.176103Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_ABCB_RECURSIVE"::Istanbul::0
2023-01-27T01:19:59.176106Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcallcode_ABCB_RECURSIVE.json"
2023-01-27T01:19:59.176109Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:59.176111Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:59.558188Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_ABCB_RECURSIVE"
2023-01-27T01:19:59.558204Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543546,
    events_root: None,
}
2023-01-27T01:19:59.558212Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=36): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:59.558226Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:19:59.558230Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_ABCB_RECURSIVE"::Berlin::0
2023-01-27T01:19:59.558232Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcallcode_ABCB_RECURSIVE.json"
2023-01-27T01:19:59.558235Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:59.558236Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:59.558374Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_ABCB_RECURSIVE"
2023-01-27T01:19:59.558379Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543546,
    events_root: None,
}
2023-01-27T01:19:59.558382Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=36): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:59.558392Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:19:59.558396Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_ABCB_RECURSIVE"::London::0
2023-01-27T01:19:59.558399Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcallcode_ABCB_RECURSIVE.json"
2023-01-27T01:19:59.558402Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:59.558403Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:59.558536Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_ABCB_RECURSIVE"
2023-01-27T01:19:59.558543Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543546,
    events_root: None,
}
2023-01-27T01:19:59.558547Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=36): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:59.558558Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:19:59.558561Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_ABCB_RECURSIVE"::Merge::0
2023-01-27T01:19:59.558563Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcallcode_ABCB_RECURSIVE.json"
2023-01-27T01:19:59.558566Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:59.558568Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:19:59.558691Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_ABCB_RECURSIVE"
2023-01-27T01:19:59.558697Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543546,
    events_root: None,
}
2023-01-27T01:19:59.558702Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=36): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:19:59.560794Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:383.013337ms
2023-01-27T01:19:59.835037Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcode_11.json", Total Files :: 1
2023-01-27T01:19:59.877287Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:19:59.877429Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:59.877433Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:19:59.877492Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:59.877494Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:19:59.877555Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:59.877558Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:19:59.877615Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:19:59.877691Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:19:59.877694Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11"::Istanbul::0
2023-01-27T01:19:59.877696Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcode_11.json"
2023-01-27T01:19:59.877700Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:19:59.877701Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:00.240069Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcode_11"
2023-01-27T01:20:00.240093Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:00.240102Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:00.240119Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:20:00.240124Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11"::Berlin::0
2023-01-27T01:20:00.240127Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcode_11.json"
2023-01-27T01:20:00.240130Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:00.240133Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:00.240269Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcode_11"
2023-01-27T01:20:00.240274Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:00.240277Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:00.240286Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:20:00.240288Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11"::London::0
2023-01-27T01:20:00.240289Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcode_11.json"
2023-01-27T01:20:00.240292Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:00.240294Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:00.240385Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcode_11"
2023-01-27T01:20:00.240389Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:00.240392Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:00.240401Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:20:00.240403Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11"::Merge::0
2023-01-27T01:20:00.240406Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcode_11.json"
2023-01-27T01:20:00.240408Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:00.240410Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:00.240497Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcode_11"
2023-01-27T01:20:00.240501Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:00.240504Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:00.242489Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:363.230984ms
2023-01-27T01:20:00.515113Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcode_11_OOGE.json", Total Files :: 1
2023-01-27T01:20:00.547366Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:20:00.547506Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:00.547510Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:20:00.547565Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:00.547567Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:20:00.547628Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:00.547630Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:20:00.547687Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:00.547761Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:20:00.547764Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11_OOGE"::Istanbul::0
2023-01-27T01:20:00.547767Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcode_11_OOGE.json"
2023-01-27T01:20:00.547770Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:00.547771Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:00.943709Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcode_11_OOGE"
2023-01-27T01:20:00.943725Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:00.943732Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:00.943745Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:20:00.943749Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11_OOGE"::Berlin::0
2023-01-27T01:20:00.943751Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcode_11_OOGE.json"
2023-01-27T01:20:00.943754Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:00.943756Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:00.943877Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcode_11_OOGE"
2023-01-27T01:20:00.943882Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:00.943885Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:00.943893Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:20:00.943896Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11_OOGE"::London::0
2023-01-27T01:20:00.943897Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcode_11_OOGE.json"
2023-01-27T01:20:00.943901Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:00.943902Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:00.943991Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcode_11_OOGE"
2023-01-27T01:20:00.943995Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:00.943998Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:00.944006Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:20:00.944008Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11_OOGE"::Merge::0
2023-01-27T01:20:00.944010Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcode_11_OOGE.json"
2023-01-27T01:20:00.944013Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:00.944014Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:00.944101Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcode_11_OOGE"
2023-01-27T01:20:00.944105Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:00.944108Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:00.945806Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:396.755286ms
2023-01-27T01:20:01.222772Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcode_11_SuicideEnd.json", Total Files :: 1
2023-01-27T01:20:01.267202Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:20:01.267345Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:01.267349Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:20:01.267404Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:01.267406Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:20:01.267466Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:01.267468Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:20:01.267523Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:01.267600Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:20:01.267603Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11_SuicideEnd"::Istanbul::0
2023-01-27T01:20:01.267605Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcode_11_SuicideEnd.json"
2023-01-27T01:20:01.267609Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:01.267610Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:01.622907Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcode_11_SuicideEnd"
2023-01-27T01:20:01.622924Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:01.622930Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:01.622943Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:20:01.622947Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11_SuicideEnd"::Berlin::0
2023-01-27T01:20:01.622949Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcode_11_SuicideEnd.json"
2023-01-27T01:20:01.622952Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:01.622955Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:01.623059Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcode_11_SuicideEnd"
2023-01-27T01:20:01.623063Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:01.623066Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:01.623076Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:20:01.623078Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11_SuicideEnd"::London::0
2023-01-27T01:20:01.623080Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcode_11_SuicideEnd.json"
2023-01-27T01:20:01.623083Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:01.623084Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:01.623168Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcode_11_SuicideEnd"
2023-01-27T01:20:01.623172Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:01.623175Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:01.623183Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:20:01.623186Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11_SuicideEnd"::Merge::0
2023-01-27T01:20:01.623188Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcode_11_SuicideEnd.json"
2023-01-27T01:20:01.623191Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:01.623192Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:01.623280Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcode_11_SuicideEnd"
2023-01-27T01:20:01.623284Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:01.623287Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:01.624739Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:356.098697ms
2023-01-27T01:20:01.917291Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecall_110.json", Total Files :: 1
2023-01-27T01:20:01.949250Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:20:01.949396Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:01.949400Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:20:01.949455Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:01.949457Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:20:01.949518Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:01.949520Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:20:01.949578Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:01.949580Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:20:01.949634Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:01.949714Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:20:01.949717Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110"::Istanbul::0
2023-01-27T01:20:01.949721Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecall_110.json"
2023-01-27T01:20:01.949724Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:01.949726Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:02.386501Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110"
2023-01-27T01:20:02.386517Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:02.386524Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:02.386539Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:20:02.386545Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110"::Berlin::0
2023-01-27T01:20:02.386548Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecall_110.json"
2023-01-27T01:20:02.386553Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:02.386554Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:02.386666Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110"
2023-01-27T01:20:02.386670Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:02.386674Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:02.386686Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:20:02.386689Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110"::London::0
2023-01-27T01:20:02.386691Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecall_110.json"
2023-01-27T01:20:02.386695Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:02.386697Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:02.386790Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110"
2023-01-27T01:20:02.386794Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:02.386798Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:02.386809Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:20:02.386812Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110"::Merge::0
2023-01-27T01:20:02.386815Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecall_110.json"
2023-01-27T01:20:02.386819Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:02.386820Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:02.386914Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110"
2023-01-27T01:20:02.386918Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:02.386921Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:02.388549Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:437.687832ms
2023-01-27T01:20:02.660450Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecall_110_OOGE.json", Total Files :: 1
2023-01-27T01:20:02.696190Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:20:02.696332Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:02.696336Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:20:02.696391Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:02.696393Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:20:02.696453Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:02.696455Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:20:02.696511Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:02.696513Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:20:02.696579Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:02.696657Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:20:02.696660Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_OOGE"::Istanbul::0
2023-01-27T01:20:02.696664Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecall_110_OOGE.json"
2023-01-27T01:20:02.696668Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:02.696669Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:03.063726Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_OOGE"
2023-01-27T01:20:03.063741Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:03.063747Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:03.063761Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:20:03.063765Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_OOGE"::Berlin::0
2023-01-27T01:20:03.063767Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecall_110_OOGE.json"
2023-01-27T01:20:03.063770Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:03.063771Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:03.063896Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_OOGE"
2023-01-27T01:20:03.063900Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:03.063903Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:03.063913Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:20:03.063915Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_OOGE"::London::0
2023-01-27T01:20:03.063917Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecall_110_OOGE.json"
2023-01-27T01:20:03.063920Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:03.063921Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:03.064012Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_OOGE"
2023-01-27T01:20:03.064016Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:03.064019Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:03.064027Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:20:03.064029Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_OOGE"::Merge::0
2023-01-27T01:20:03.064031Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecall_110_OOGE.json"
2023-01-27T01:20:03.064034Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:03.064036Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:03.064125Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_OOGE"
2023-01-27T01:20:03.064129Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:03.064131Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:03.065441Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:367.955708ms
2023-01-27T01:20:03.327847Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecall_110_OOGMAfter.json", Total Files :: 1
2023-01-27T01:20:03.385636Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:20:03.385806Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:03.385811Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:20:03.385867Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:03.385870Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:20:03.385932Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:03.385935Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:20:03.385993Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:03.385996Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:20:03.386056Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:03.386149Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:20:03.386153Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_OOGMAfter"::Istanbul::0
2023-01-27T01:20:03.386157Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecall_110_OOGMAfter.json"
2023-01-27T01:20:03.386161Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:03.386163Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:03.804421Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_OOGMAfter"
2023-01-27T01:20:03.804436Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544011,
    events_root: None,
}
2023-01-27T01:20:03.804443Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:03.804456Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:20:03.804460Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_OOGMAfter"::Berlin::0
2023-01-27T01:20:03.804462Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecall_110_OOGMAfter.json"
2023-01-27T01:20:03.804465Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:03.804467Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:03.804603Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_OOGMAfter"
2023-01-27T01:20:03.804608Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544011,
    events_root: None,
}
2023-01-27T01:20:03.804611Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:03.804621Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:20:03.804623Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_OOGMAfter"::London::0
2023-01-27T01:20:03.804625Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecall_110_OOGMAfter.json"
2023-01-27T01:20:03.804628Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:03.804629Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:03.804718Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_OOGMAfter"
2023-01-27T01:20:03.804722Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544011,
    events_root: None,
}
2023-01-27T01:20:03.804726Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:03.804734Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:20:03.804737Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_OOGMAfter"::Merge::0
2023-01-27T01:20:03.804739Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecall_110_OOGMAfter.json"
2023-01-27T01:20:03.804742Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:03.804743Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:03.804834Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_OOGMAfter"
2023-01-27T01:20:03.804839Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544011,
    events_root: None,
}
2023-01-27T01:20:03.804842Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:03.806475Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:419.222036ms
2023-01-27T01:20:04.085108Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecall_110_OOGMBefore.json", Total Files :: 1
2023-01-27T01:20:04.115637Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:20:04.115776Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:04.115781Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:20:04.115831Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:04.115833Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:20:04.115891Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:04.115894Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:20:04.115949Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:04.115952Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:20:04.116003Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:04.116080Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:20:04.116083Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_OOGMBefore"::Istanbul::0
2023-01-27T01:20:04.116086Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecall_110_OOGMBefore.json"
2023-01-27T01:20:04.116090Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:04.116091Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:04.461176Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_OOGMBefore"
2023-01-27T01:20:04.461198Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:04.461208Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:04.461222Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:20:04.461226Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_OOGMBefore"::Berlin::0
2023-01-27T01:20:04.461228Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecall_110_OOGMBefore.json"
2023-01-27T01:20:04.461232Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:04.461234Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:04.461362Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_OOGMBefore"
2023-01-27T01:20:04.461367Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:04.461370Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:04.461378Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:20:04.461381Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_OOGMBefore"::London::0
2023-01-27T01:20:04.461383Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecall_110_OOGMBefore.json"
2023-01-27T01:20:04.461385Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:04.461387Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:04.461477Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_OOGMBefore"
2023-01-27T01:20:04.461481Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:04.461483Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:04.461492Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:20:04.461494Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_OOGMBefore"::Merge::0
2023-01-27T01:20:04.461495Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecall_110_OOGMBefore.json"
2023-01-27T01:20:04.461498Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:04.461499Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:04.461585Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_OOGMBefore"
2023-01-27T01:20:04.461589Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:04.461592Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:04.463414Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:345.969401ms
2023-01-27T01:20:04.739839Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecall_110_SuicideEnd.json", Total Files :: 1
2023-01-27T01:20:04.772524Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:20:04.772674Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:04.772678Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:20:04.772730Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:04.772732Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:20:04.772790Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:04.772792Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:20:04.772847Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:04.772849Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:20:04.772901Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:04.772975Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:20:04.772978Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_SuicideEnd"::Istanbul::0
2023-01-27T01:20:04.772982Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecall_110_SuicideEnd.json"
2023-01-27T01:20:04.772985Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:04.772987Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:05.122402Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_SuicideEnd"
2023-01-27T01:20:05.122422Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:05.122430Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:05.122448Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:20:05.122454Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_SuicideEnd"::Berlin::0
2023-01-27T01:20:05.122458Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecall_110_SuicideEnd.json"
2023-01-27T01:20:05.122463Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:05.122465Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:05.122605Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_SuicideEnd"
2023-01-27T01:20:05.122613Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:05.122616Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:05.122627Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:20:05.122629Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_SuicideEnd"::London::0
2023-01-27T01:20:05.122633Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecall_110_SuicideEnd.json"
2023-01-27T01:20:05.122637Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:05.122639Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:05.122758Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_SuicideEnd"
2023-01-27T01:20:05.122763Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:05.122768Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:05.122779Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:20:05.122782Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_SuicideEnd"::Merge::0
2023-01-27T01:20:05.122784Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecall_110_SuicideEnd.json"
2023-01-27T01:20:05.122788Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:05.122790Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:05.122923Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_SuicideEnd"
2023-01-27T01:20:05.122930Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:05.122933Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:05.124691Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:350.42625ms
2023-01-27T01:20:05.391214Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecall_110_SuicideMiddle.json", Total Files :: 1
2023-01-27T01:20:05.425622Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:20:05.425764Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:05.425767Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:20:05.425819Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:05.425821Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:20:05.425884Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:05.425886Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:20:05.425941Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:05.425943Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:20:05.425995Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:05.426069Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:20:05.426072Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_SuicideMiddle"::Istanbul::0
2023-01-27T01:20:05.426075Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecall_110_SuicideMiddle.json"
2023-01-27T01:20:05.426078Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:05.426080Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:05.844229Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_SuicideMiddle"
2023-01-27T01:20:05.844245Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:05.844252Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:05.844265Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:20:05.844268Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_SuicideMiddle"::Berlin::0
2023-01-27T01:20:05.844270Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecall_110_SuicideMiddle.json"
2023-01-27T01:20:05.844274Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:05.844275Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:05.844397Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_SuicideMiddle"
2023-01-27T01:20:05.844401Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:05.844404Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:05.844413Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:20:05.844415Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_SuicideMiddle"::London::0
2023-01-27T01:20:05.844417Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecall_110_SuicideMiddle.json"
2023-01-27T01:20:05.844419Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:05.844421Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:05.844508Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_SuicideMiddle"
2023-01-27T01:20:05.844511Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:05.844514Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:05.844523Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:20:05.844525Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_SuicideMiddle"::Merge::0
2023-01-27T01:20:05.844526Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecall_110_SuicideMiddle.json"
2023-01-27T01:20:05.844536Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:05.844538Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:05.844633Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_SuicideMiddle"
2023-01-27T01:20:05.844639Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:05.844644Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:05.846051Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:419.037641ms
2023-01-27T01:20:06.135619Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecall_ABCB_RECURSIVE.json", Total Files :: 1
2023-01-27T01:20:06.200757Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:20:06.201017Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:06.201023Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:20:06.201140Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:06.201143Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:20:06.201267Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:06.201272Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:20:06.201391Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:06.201585Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:20:06.201590Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_ABCB_RECURSIVE"::Istanbul::0
2023-01-27T01:20:06.201594Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecall_ABCB_RECURSIVE.json"
2023-01-27T01:20:06.201598Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:06.201600Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:06.591360Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_ABCB_RECURSIVE"
2023-01-27T01:20:06.591377Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543546,
    events_root: None,
}
2023-01-27T01:20:06.591385Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=36): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:06.591399Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:20:06.591403Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_ABCB_RECURSIVE"::Berlin::0
2023-01-27T01:20:06.591405Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecall_ABCB_RECURSIVE.json"
2023-01-27T01:20:06.591409Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:06.591410Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:06.591545Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_ABCB_RECURSIVE"
2023-01-27T01:20:06.591551Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543546,
    events_root: None,
}
2023-01-27T01:20:06.591555Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=36): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:06.591564Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:20:06.591568Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_ABCB_RECURSIVE"::London::0
2023-01-27T01:20:06.591570Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecall_ABCB_RECURSIVE.json"
2023-01-27T01:20:06.591573Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:06.591574Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:06.591673Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_ABCB_RECURSIVE"
2023-01-27T01:20:06.591677Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543546,
    events_root: None,
}
2023-01-27T01:20:06.591680Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=36): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:06.591688Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:20:06.591692Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_ABCB_RECURSIVE"::Merge::0
2023-01-27T01:20:06.591694Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecall_ABCB_RECURSIVE.json"
2023-01-27T01:20:06.591696Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:06.591698Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:06.591785Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_ABCB_RECURSIVE"
2023-01-27T01:20:06.591789Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543546,
    events_root: None,
}
2023-01-27T01:20:06.591793Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=36): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:06.593495Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:391.049877ms
2023-01-27T01:20:06.875499Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecallcode_111.json", Total Files :: 1
2023-01-27T01:20:06.906643Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:20:06.906780Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:06.906784Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:20:06.906836Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:06.906838Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:20:06.906896Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:06.906898Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:20:06.906954Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:06.906957Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:20:06.907008Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:06.907086Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:20:06.907089Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111"::Istanbul::0
2023-01-27T01:20:06.907092Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecallcode_111.json"
2023-01-27T01:20:06.907095Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:06.907097Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:07.265902Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111"
2023-01-27T01:20:07.265918Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:07.265925Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:07.265938Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:20:07.265942Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111"::Berlin::0
2023-01-27T01:20:07.265944Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecallcode_111.json"
2023-01-27T01:20:07.265946Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:07.265949Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:07.266059Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111"
2023-01-27T01:20:07.266063Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:07.266066Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:07.266076Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:20:07.266079Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111"::London::0
2023-01-27T01:20:07.266081Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecallcode_111.json"
2023-01-27T01:20:07.266083Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:07.266084Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:07.266170Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111"
2023-01-27T01:20:07.266174Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:07.266177Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:07.266185Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:20:07.266187Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111"::Merge::0
2023-01-27T01:20:07.266189Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecallcode_111.json"
2023-01-27T01:20:07.266191Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:07.266193Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:07.266296Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111"
2023-01-27T01:20:07.266301Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:07.266304Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:07.267715Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:359.676882ms
2023-01-27T01:20:07.526258Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecallcode_111_OOGE.json", Total Files :: 1
2023-01-27T01:20:07.622390Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:20:07.622560Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:07.622565Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:20:07.622619Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:07.622621Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:20:07.622680Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:07.622682Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:20:07.622739Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:07.622742Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:20:07.622794Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:07.622878Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:20:07.622882Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_OOGE"::Istanbul::0
2023-01-27T01:20:07.622885Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecallcode_111_OOGE.json"
2023-01-27T01:20:07.622888Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:07.622889Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:07.981599Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_OOGE"
2023-01-27T01:20:07.981615Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:07.981622Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:07.981636Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:20:07.981640Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_OOGE"::Berlin::0
2023-01-27T01:20:07.981641Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecallcode_111_OOGE.json"
2023-01-27T01:20:07.981645Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:07.981646Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:07.981771Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_OOGE"
2023-01-27T01:20:07.981776Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:07.981779Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:07.981787Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:20:07.981789Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_OOGE"::London::0
2023-01-27T01:20:07.981791Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecallcode_111_OOGE.json"
2023-01-27T01:20:07.981794Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:07.981795Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:07.981884Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_OOGE"
2023-01-27T01:20:07.981888Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:07.981892Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:07.981902Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:20:07.981904Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_OOGE"::Merge::0
2023-01-27T01:20:07.981906Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecallcode_111_OOGE.json"
2023-01-27T01:20:07.981910Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:07.981912Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:07.982024Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_OOGE"
2023-01-27T01:20:07.982030Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:07.982033Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:07.983464Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:359.658283ms
2023-01-27T01:20:08.258260Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecallcode_111_OOGMAfter.json", Total Files :: 1
2023-01-27T01:20:08.289475Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:20:08.289615Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:08.289619Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:20:08.289672Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:08.289674Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:20:08.289733Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:08.289735Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:20:08.289792Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:08.289794Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:20:08.289847Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:08.289922Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:20:08.289925Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_OOGMAfter"::Istanbul::0
2023-01-27T01:20:08.289928Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecallcode_111_OOGMAfter.json"
2023-01-27T01:20:08.289931Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:08.289933Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:08.634315Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_OOGMAfter"
2023-01-27T01:20:08.634331Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544011,
    events_root: None,
}
2023-01-27T01:20:08.634338Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:08.634351Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:20:08.634355Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_OOGMAfter"::Berlin::0
2023-01-27T01:20:08.634357Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecallcode_111_OOGMAfter.json"
2023-01-27T01:20:08.634360Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:08.634361Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:08.634491Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_OOGMAfter"
2023-01-27T01:20:08.634497Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544011,
    events_root: None,
}
2023-01-27T01:20:08.634500Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:08.634508Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:20:08.634510Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_OOGMAfter"::London::0
2023-01-27T01:20:08.634513Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecallcode_111_OOGMAfter.json"
2023-01-27T01:20:08.634515Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:08.634517Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:08.634606Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_OOGMAfter"
2023-01-27T01:20:08.634611Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544011,
    events_root: None,
}
2023-01-27T01:20:08.634613Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:08.634622Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:20:08.634624Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_OOGMAfter"::Merge::0
2023-01-27T01:20:08.634626Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecallcode_111_OOGMAfter.json"
2023-01-27T01:20:08.634628Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:08.634630Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:08.634717Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_OOGMAfter"
2023-01-27T01:20:08.634721Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1544011,
    events_root: None,
}
2023-01-27T01:20:08.634723Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:08.636409Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:345.262003ms
2023-01-27T01:20:08.921278Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecallcode_111_OOGMBefore.json", Total Files :: 1
2023-01-27T01:20:08.952482Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:20:08.952631Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:08.952636Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:20:08.952690Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:08.952692Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:20:08.952752Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:08.952755Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:20:08.952813Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:08.952815Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:20:08.952870Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:08.952949Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:20:08.952952Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_OOGMBefore"::Istanbul::0
2023-01-27T01:20:08.952955Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecallcode_111_OOGMBefore.json"
2023-01-27T01:20:08.952958Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:08.952959Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:09.342877Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_OOGMBefore"
2023-01-27T01:20:09.342897Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:09.342905Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:09.342923Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:20:09.342929Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_OOGMBefore"::Berlin::0
2023-01-27T01:20:09.342932Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecallcode_111_OOGMBefore.json"
2023-01-27T01:20:09.342937Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:09.342939Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:09.343115Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_OOGMBefore"
2023-01-27T01:20:09.343123Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:09.343127Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:09.343138Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:20:09.343140Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_OOGMBefore"::London::0
2023-01-27T01:20:09.343142Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecallcode_111_OOGMBefore.json"
2023-01-27T01:20:09.343144Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:09.343146Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:09.343247Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_OOGMBefore"
2023-01-27T01:20:09.343251Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:09.343255Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:09.343263Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:20:09.343265Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_OOGMBefore"::Merge::0
2023-01-27T01:20:09.343267Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecallcode_111_OOGMBefore.json"
2023-01-27T01:20:09.343270Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:09.343271Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:09.343375Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_OOGMBefore"
2023-01-27T01:20:09.343380Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:09.343383Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:09.345237Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:390.916257ms
2023-01-27T01:20:09.613687Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecallcode_111_SuicideEnd.json", Total Files :: 1
2023-01-27T01:20:09.674940Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:20:09.675082Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:09.675086Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:20:09.675141Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:09.675143Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:20:09.675205Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:09.675207Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:20:09.675264Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:09.675267Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:20:09.675321Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:09.675397Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:20:09.675401Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_SuicideEnd"::Istanbul::0
2023-01-27T01:20:09.675404Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecallcode_111_SuicideEnd.json"
2023-01-27T01:20:09.675407Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:09.675409Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:10.061807Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_SuicideEnd"
2023-01-27T01:20:10.061823Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:10.061830Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:10.061845Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:20:10.061849Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_SuicideEnd"::Berlin::0
2023-01-27T01:20:10.061851Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecallcode_111_SuicideEnd.json"
2023-01-27T01:20:10.061854Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:10.061856Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:10.061964Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_SuicideEnd"
2023-01-27T01:20:10.061970Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:10.061973Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:10.061982Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:20:10.061984Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_SuicideEnd"::London::0
2023-01-27T01:20:10.061986Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecallcode_111_SuicideEnd.json"
2023-01-27T01:20:10.061989Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:10.061990Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:10.062080Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_SuicideEnd"
2023-01-27T01:20:10.062086Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:10.062091Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:10.062103Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:20:10.062105Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_SuicideEnd"::Merge::0
2023-01-27T01:20:10.062109Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecallcode_111_SuicideEnd.json"
2023-01-27T01:20:10.062112Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:10.062114Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:10.062212Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_SuicideEnd"
2023-01-27T01:20:10.062216Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:10.062219Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:10.063701Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:387.293169ms
2023-01-27T01:20:10.349898Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecallcode_111_SuicideMiddle.json", Total Files :: 1
2023-01-27T01:20:10.395006Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:20:10.395140Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:10.395143Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:20:10.395195Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:10.395197Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:20:10.395261Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:10.395263Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:20:10.395318Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:10.395320Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-27T01:20:10.395371Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:10.395446Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:20:10.395449Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_SuicideMiddle"::Istanbul::0
2023-01-27T01:20:10.395452Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecallcode_111_SuicideMiddle.json"
2023-01-27T01:20:10.395456Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:10.395457Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:10.735323Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_SuicideMiddle"
2023-01-27T01:20:10.735339Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:10.735346Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:10.735359Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:20:10.735363Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_SuicideMiddle"::Berlin::0
2023-01-27T01:20:10.735365Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecallcode_111_SuicideMiddle.json"
2023-01-27T01:20:10.735368Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:10.735371Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:10.735493Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_SuicideMiddle"
2023-01-27T01:20:10.735497Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:10.735500Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:10.735508Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:20:10.735510Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_SuicideMiddle"::London::0
2023-01-27T01:20:10.735512Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecallcode_111_SuicideMiddle.json"
2023-01-27T01:20:10.735515Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:10.735516Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:10.735599Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_SuicideMiddle"
2023-01-27T01:20:10.735604Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:10.735606Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:10.735615Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:20:10.735617Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_SuicideMiddle"::Merge::0
2023-01-27T01:20:10.735618Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecallcode_111_SuicideMiddle.json"
2023-01-27T01:20:10.735621Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:10.735623Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:10.735706Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_SuicideMiddle"
2023-01-27T01:20:10.735710Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543459,
    events_root: None,
}
2023-01-27T01:20:10.735714Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=35): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:10.737284Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:340.723105ms
2023-01-27T01:20:11.022486Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecallcode_ABCB_RECURSIVE.json", Total Files :: 1
2023-01-27T01:20:11.083644Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:20:11.083776Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:11.083779Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:20:11.083830Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:11.083833Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:20:11.083890Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:11.083893Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-27T01:20:11.083946Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:11.084018Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:20:11.084022Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_ABCB_RECURSIVE"::Istanbul::0
2023-01-27T01:20:11.084024Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecallcode_ABCB_RECURSIVE.json"
2023-01-27T01:20:11.084028Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:11.084029Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:11.449896Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_ABCB_RECURSIVE"
2023-01-27T01:20:11.449912Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543546,
    events_root: None,
}
2023-01-27T01:20:11.449919Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=36): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:11.449934Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:20:11.449937Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_ABCB_RECURSIVE"::Berlin::0
2023-01-27T01:20:11.449939Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecallcode_ABCB_RECURSIVE.json"
2023-01-27T01:20:11.449943Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:11.449944Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:11.450044Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_ABCB_RECURSIVE"
2023-01-27T01:20:11.450048Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543546,
    events_root: None,
}
2023-01-27T01:20:11.450051Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=36): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:11.450059Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:20:11.450061Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_ABCB_RECURSIVE"::London::0
2023-01-27T01:20:11.450063Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecallcode_ABCB_RECURSIVE.json"
2023-01-27T01:20:11.450066Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:11.450067Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:11.450149Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_ABCB_RECURSIVE"
2023-01-27T01:20:11.450152Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543546,
    events_root: None,
}
2023-01-27T01:20:11.450155Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=36): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:11.450163Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:20:11.450165Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_ABCB_RECURSIVE"::Merge::0
2023-01-27T01:20:11.450167Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/callcodecallcodecallcode_ABCB_RECURSIVE.json"
2023-01-27T01:20:11.450170Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:11.450171Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:11.450255Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_ABCB_RECURSIVE"
2023-01-27T01:20:11.450259Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1543546,
    events_root: None,
}
2023-01-27T01:20:11.450262Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=36): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T01:20:11.451859Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:366.631017ms
2023-01-27T01:20:11.719184Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallCodes/touchAndGo.json", Total Files :: 1
2023-01-27T01:20:11.781447Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T01:20:11.781586Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:11.781590Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T01:20:11.781642Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:11.781644Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-27T01:20:11.781711Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T01:20:11.781788Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP150 0
2023-01-27T01:20:11.781791Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "touchAndGo"::EIP150::0
2023-01-27T01:20:11.781794Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/touchAndGo.json"
2023-01-27T01:20:11.781797Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:11.781798Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:12.163714Z  INFO evm_eth_compliance::statetest::runner: UC : "touchAndGo"
2023-01-27T01:20:12.163733Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1701959,
    events_root: None,
}
2023-01-27T01:20:12.163746Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => EIP158 0
2023-01-27T01:20:12.163751Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "touchAndGo"::EIP158::0
2023-01-27T01:20:12.163753Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/touchAndGo.json"
2023-01-27T01:20:12.163756Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:12.163757Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:12.163885Z  INFO evm_eth_compliance::statetest::runner: UC : "touchAndGo"
2023-01-27T01:20:12.163889Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1701959,
    events_root: None,
}
2023-01-27T01:20:12.163896Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Byzantium 0
2023-01-27T01:20:12.163898Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "touchAndGo"::Byzantium::0
2023-01-27T01:20:12.163899Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/touchAndGo.json"
2023-01-27T01:20:12.163902Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:12.163903Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:12.164034Z  INFO evm_eth_compliance::statetest::runner: UC : "touchAndGo"
2023-01-27T01:20:12.164039Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1701959,
    events_root: None,
}
2023-01-27T01:20:12.164045Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Constantinople 0
2023-01-27T01:20:12.164048Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "touchAndGo"::Constantinople::0
2023-01-27T01:20:12.164050Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/touchAndGo.json"
2023-01-27T01:20:12.164053Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:12.164055Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:12.164167Z  INFO evm_eth_compliance::statetest::runner: UC : "touchAndGo"
2023-01-27T01:20:12.164172Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1701959,
    events_root: None,
}
2023-01-27T01:20:12.164179Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => ConstantinopleFix 0
2023-01-27T01:20:12.164181Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "touchAndGo"::ConstantinopleFix::0
2023-01-27T01:20:12.164184Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/touchAndGo.json"
2023-01-27T01:20:12.164187Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:12.164189Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:12.164298Z  INFO evm_eth_compliance::statetest::runner: UC : "touchAndGo"
2023-01-27T01:20:12.164303Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1701959,
    events_root: None,
}
2023-01-27T01:20:12.164310Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T01:20:12.164312Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "touchAndGo"::Istanbul::0
2023-01-27T01:20:12.164315Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/touchAndGo.json"
2023-01-27T01:20:12.164318Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:12.164320Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:12.164429Z  INFO evm_eth_compliance::statetest::runner: UC : "touchAndGo"
2023-01-27T01:20:12.164433Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1701959,
    events_root: None,
}
2023-01-27T01:20:12.164440Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T01:20:12.164443Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "touchAndGo"::Berlin::0
2023-01-27T01:20:12.164445Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/touchAndGo.json"
2023-01-27T01:20:12.164448Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:12.164450Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:12.164567Z  INFO evm_eth_compliance::statetest::runner: UC : "touchAndGo"
2023-01-27T01:20:12.164572Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1701959,
    events_root: None,
}
2023-01-27T01:20:12.164579Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T01:20:12.164584Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "touchAndGo"::London::0
2023-01-27T01:20:12.164588Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/touchAndGo.json"
2023-01-27T01:20:12.164591Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:12.164593Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:12.164704Z  INFO evm_eth_compliance::statetest::runner: UC : "touchAndGo"
2023-01-27T01:20:12.164708Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1701959,
    events_root: None,
}
2023-01-27T01:20:12.164715Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T01:20:12.164717Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "touchAndGo"::Merge::0
2023-01-27T01:20:12.164720Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallCodes/touchAndGo.json"
2023-01-27T01:20:12.164723Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T01:20:12.164726Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T01:20:12.164835Z  INFO evm_eth_compliance::statetest::runner: UC : "touchAndGo"
2023-01-27T01:20:12.164840Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1701959,
    events_root: None,
}
2023-01-27T01:20:12.166625Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:383.404324ms
```
