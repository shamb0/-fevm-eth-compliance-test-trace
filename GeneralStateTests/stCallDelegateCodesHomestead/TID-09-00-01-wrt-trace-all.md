> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stCallDelegateCodesHomestead

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead \
	cargo run --release \
	-- \
	statetest
```

> For Review

* Execution looks OK, all use-cases passed

> Execution Trace

```
2023-01-26T16:06:02.901277Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcallcode_001.json", Total Files :: 1
2023-01-26T16:06:02.931066Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:02.931210Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:02.931214Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:02.931270Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:02.931273Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:02.931336Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:02.931338Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:02.931399Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:02.931402Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:02.931459Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:02.931534Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:02.931537Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001"::Istanbul::0
2023-01-26T16:06:02.931541Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcallcode_001.json"
2023-01-26T16:06:02.931546Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:02.931548Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:03.283679Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001"
2023-01-26T16:06:03.283697Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-26T16:06:03.283710Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:03.283716Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001"::Berlin::0
2023-01-26T16:06:03.283717Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcallcode_001.json"
2023-01-26T16:06:03.283721Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:03.283722Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:03.283852Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001"
2023-01-26T16:06:03.283857Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-26T16:06:03.283864Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:03.283866Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001"::London::0
2023-01-26T16:06:03.283868Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcallcode_001.json"
2023-01-26T16:06:03.283872Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:03.283873Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:03.283987Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001"
2023-01-26T16:06:03.283992Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-26T16:06:03.283997Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:03.284000Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001"::Merge::0
2023-01-26T16:06:03.284001Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcallcode_001.json"
2023-01-26T16:06:03.284004Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:03.284005Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:03.284118Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001"
2023-01-26T16:06:03.284123Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-26T16:06:03.285745Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:353.067315ms
2023-01-26T16:06:03.564938Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcallcode_001_OOGE.json", Total Files :: 1
2023-01-26T16:06:03.594348Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:03.594495Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:03.594500Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:03.594555Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:03.594557Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:03.594617Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:03.594619Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:03.594675Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:03.594677Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:03.594729Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:03.594803Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:03.594806Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_OOGE"::Istanbul::0
2023-01-26T16:06:03.594809Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcallcode_001_OOGE.json"
2023-01-26T16:06:03.594813Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:03.594814Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:03.946608Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_OOGE"
2023-01-26T16:06:03.946624Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-26T16:06:03.946636Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:03.946641Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_OOGE"::Berlin::0
2023-01-26T16:06:03.946643Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcallcode_001_OOGE.json"
2023-01-26T16:06:03.946646Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:03.946647Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:03.946826Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_OOGE"
2023-01-26T16:06:03.946831Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-26T16:06:03.946837Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:03.946839Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_OOGE"::London::0
2023-01-26T16:06:03.946841Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcallcode_001_OOGE.json"
2023-01-26T16:06:03.946844Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:03.946845Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:03.947010Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_OOGE"
2023-01-26T16:06:03.947016Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-26T16:06:03.947022Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:03.947024Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_OOGE"::Merge::0
2023-01-26T16:06:03.947026Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcallcode_001_OOGE.json"
2023-01-26T16:06:03.947028Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:03.947030Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:03.947190Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_OOGE"
2023-01-26T16:06:03.947195Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-26T16:06:03.948788Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:352.857249ms
2023-01-26T16:06:04.207965Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcallcode_001_OOGMAfter.json", Total Files :: 1
2023-01-26T16:06:04.238605Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:04.238744Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:04.238747Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:04.238800Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:04.238802Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:04.238863Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:04.238865Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:04.238923Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:04.238926Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:04.238979Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:04.239054Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:04.239057Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_OOGMAfter"::Istanbul::0
2023-01-26T16:06:04.239060Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcallcode_001_OOGMAfter.json"
2023-01-26T16:06:04.239064Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:04.239065Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:04.605313Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_OOGMAfter"
2023-01-26T16:06:04.605329Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3457188,
    events_root: None,
}
2023-01-26T16:06:04.605341Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:04.605345Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_OOGMAfter"::Berlin::0
2023-01-26T16:06:04.605347Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcallcode_001_OOGMAfter.json"
2023-01-26T16:06:04.605350Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:04.605352Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:04.605531Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_OOGMAfter"
2023-01-26T16:06:04.605536Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2558154,
    events_root: None,
}
2023-01-26T16:06:04.605542Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:04.605544Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_OOGMAfter"::London::0
2023-01-26T16:06:04.605547Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcallcode_001_OOGMAfter.json"
2023-01-26T16:06:04.605550Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:04.605552Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:04.605762Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_OOGMAfter"
2023-01-26T16:06:04.605768Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2558154,
    events_root: None,
}
2023-01-26T16:06:04.605776Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:04.605779Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_OOGMAfter"::Merge::0
2023-01-26T16:06:04.605782Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcallcode_001_OOGMAfter.json"
2023-01-26T16:06:04.605786Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:04.605788Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:04.605953Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_OOGMAfter"
2023-01-26T16:06:04.605957Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2558154,
    events_root: None,
}
2023-01-26T16:06:04.607609Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:367.36245ms
2023-01-26T16:06:04.867414Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcallcode_001_OOGMBefore.json", Total Files :: 1
2023-01-26T16:06:04.897372Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:04.897523Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:04.897528Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:04.897583Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:04.897586Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:04.897647Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:04.897649Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:04.897706Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:04.897709Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:04.897762Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:04.897838Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:04.897841Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_OOGMBefore"::Istanbul::0
2023-01-26T16:06:04.897845Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcallcode_001_OOGMBefore.json"
2023-01-26T16:06:04.897848Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:04.897850Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:05.263657Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_OOGMBefore"
2023-01-26T16:06:05.263673Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-26T16:06:05.263684Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:05.263688Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_OOGMBefore"::Berlin::0
2023-01-26T16:06:05.263690Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcallcode_001_OOGMBefore.json"
2023-01-26T16:06:05.263693Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:05.263694Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:05.263866Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_OOGMBefore"
2023-01-26T16:06:05.263871Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-26T16:06:05.263877Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:05.263880Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_OOGMBefore"::London::0
2023-01-26T16:06:05.263882Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcallcode_001_OOGMBefore.json"
2023-01-26T16:06:05.263885Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:05.263886Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:05.264047Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_OOGMBefore"
2023-01-26T16:06:05.264052Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-26T16:06:05.264058Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:05.264060Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_OOGMBefore"::Merge::0
2023-01-26T16:06:05.264061Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcallcode_001_OOGMBefore.json"
2023-01-26T16:06:05.264064Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:05.264066Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:05.264224Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_OOGMBefore"
2023-01-26T16:06:05.264230Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-26T16:06:05.266113Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:366.868253ms
2023-01-26T16:06:05.531149Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcallcode_001_SuicideEnd.json", Total Files :: 1
2023-01-26T16:06:05.560253Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:05.560390Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:05.560394Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:05.560444Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:05.560446Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:05.560503Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:05.560505Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:05.560561Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:05.560564Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:05.560614Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:05.560685Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:05.560688Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_SuicideEnd"::Istanbul::0
2023-01-26T16:06:05.560691Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcallcode_001_SuicideEnd.json"
2023-01-26T16:06:05.560694Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:05.560696Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:05.919255Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_SuicideEnd"
2023-01-26T16:06:05.919270Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-26T16:06:05.919281Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:05.919285Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_SuicideEnd"::Berlin::0
2023-01-26T16:06:05.919287Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcallcode_001_SuicideEnd.json"
2023-01-26T16:06:05.919291Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:05.919292Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:05.919413Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_SuicideEnd"
2023-01-26T16:06:05.919417Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-26T16:06:05.919423Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:05.919425Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_SuicideEnd"::London::0
2023-01-26T16:06:05.919427Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcallcode_001_SuicideEnd.json"
2023-01-26T16:06:05.919430Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:05.919431Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:05.919536Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_SuicideEnd"
2023-01-26T16:06:05.919540Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-26T16:06:05.919546Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:05.919548Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_SuicideEnd"::Merge::0
2023-01-26T16:06:05.919549Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcallcode_001_SuicideEnd.json"
2023-01-26T16:06:05.919552Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:05.919554Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:05.919658Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_SuicideEnd"
2023-01-26T16:06:05.919662Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-26T16:06:05.921216Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:359.419126ms
2023-01-26T16:06:06.208058Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcallcode_001_SuicideMiddle.json", Total Files :: 1
2023-01-26T16:06:06.236698Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:06.236833Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:06.236837Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:06.236889Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:06.236891Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:06.236949Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:06.236951Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:06.237005Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:06.237008Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:06.237060Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:06.237131Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:06.237134Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_SuicideMiddle"::Istanbul::0
2023-01-26T16:06:06.237137Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcallcode_001_SuicideMiddle.json"
2023-01-26T16:06:06.237140Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:06.237141Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:06.582590Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_SuicideMiddle"
2023-01-26T16:06:06.582605Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-26T16:06:06.582617Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:06.582621Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_SuicideMiddle"::Berlin::0
2023-01-26T16:06:06.582623Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcallcode_001_SuicideMiddle.json"
2023-01-26T16:06:06.582626Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:06.582628Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:06.582752Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_SuicideMiddle"
2023-01-26T16:06:06.582756Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-26T16:06:06.582762Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:06.582765Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_SuicideMiddle"::London::0
2023-01-26T16:06:06.582767Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcallcode_001_SuicideMiddle.json"
2023-01-26T16:06:06.582770Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:06.582773Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:06.582884Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_SuicideMiddle"
2023-01-26T16:06:06.582889Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-26T16:06:06.582895Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:06.582898Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_001_SuicideMiddle"::Merge::0
2023-01-26T16:06:06.582900Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcallcode_001_SuicideMiddle.json"
2023-01-26T16:06:06.582903Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:06.582905Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:06.583023Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_001_SuicideMiddle"
2023-01-26T16:06:06.583028Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-26T16:06:06.584678Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:346.340132ms
2023-01-26T16:06:06.874018Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcallcode_ABCB_RECURSIVE.json", Total Files :: 1
2023-01-26T16:06:06.904517Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:06.904668Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:06.904672Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:06.904731Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:06.904733Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:06.904800Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:06.904803Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:06.904863Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:06.904939Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:06.904943Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_ABCB_RECURSIVE"::Istanbul::0
2023-01-26T16:06:06.904947Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcallcode_ABCB_RECURSIVE.json"
2023-01-26T16:06:06.904952Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:06.904955Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:07.283201Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_ABCB_RECURSIVE"
2023-01-26T16:06:07.283217Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5199360,
    events_root: None,
}
2023-01-26T16:06:07.283231Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:07.283237Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_ABCB_RECURSIVE"::Berlin::0
2023-01-26T16:06:07.283239Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcallcode_ABCB_RECURSIVE.json"
2023-01-26T16:06:07.283244Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:07.283246Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:07.283550Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_ABCB_RECURSIVE"
2023-01-26T16:06:07.283555Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4299582,
    events_root: None,
}
2023-01-26T16:06:07.283566Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:07.283569Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_ABCB_RECURSIVE"::London::0
2023-01-26T16:06:07.283572Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcallcode_ABCB_RECURSIVE.json"
2023-01-26T16:06:07.283576Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:07.283578Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:07.283850Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_ABCB_RECURSIVE"
2023-01-26T16:06:07.283856Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4299582,
    events_root: None,
}
2023-01-26T16:06:07.283867Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:07.283870Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcallcode_ABCB_RECURSIVE"::Merge::0
2023-01-26T16:06:07.283873Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcallcode_ABCB_RECURSIVE.json"
2023-01-26T16:06:07.283877Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:07.283879Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:07.284146Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcallcode_ABCB_RECURSIVE"
2023-01-26T16:06:07.284151Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4299582,
    events_root: None,
}
2023-01-26T16:06:07.285764Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:379.649863ms
2023-01-26T16:06:07.551662Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcode_01.json", Total Files :: 1
2023-01-26T16:06:07.581868Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:07.582015Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:07.582019Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:07.582074Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:07.582076Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:07.582137Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:07.582140Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:07.582198Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:07.582274Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:07.582277Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01"::Istanbul::0
2023-01-26T16:06:07.582280Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcode_01.json"
2023-01-26T16:06:07.582283Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:07.582285Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:07.948320Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcode_01"
2023-01-26T16:06:07.948336Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-26T16:06:07.948348Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:07.948353Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01"::Berlin::0
2023-01-26T16:06:07.948355Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcode_01.json"
2023-01-26T16:06:07.948359Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:07.948361Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:07.948485Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcode_01"
2023-01-26T16:06:07.948489Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-26T16:06:07.948495Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:07.948497Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01"::London::0
2023-01-26T16:06:07.948499Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcode_01.json"
2023-01-26T16:06:07.948502Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:07.948503Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:07.948611Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcode_01"
2023-01-26T16:06:07.948616Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-26T16:06:07.948621Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:07.948623Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01"::Merge::0
2023-01-26T16:06:07.948625Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcode_01.json"
2023-01-26T16:06:07.948627Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:07.948629Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:07.948753Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcode_01"
2023-01-26T16:06:07.948758Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-26T16:06:07.950404Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:366.900737ms
2023-01-26T16:06:08.215409Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcode_01_OOGE.json", Total Files :: 1
2023-01-26T16:06:08.244255Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:08.244388Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:08.244392Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:08.244444Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:08.244446Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:08.244504Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:08.244506Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:08.244561Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:08.244631Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:08.244634Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01_OOGE"::Istanbul::0
2023-01-26T16:06:08.244637Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcode_01_OOGE.json"
2023-01-26T16:06:08.244641Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:08.244642Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:08.610109Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcode_01_OOGE"
2023-01-26T16:06:08.610125Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-26T16:06:08.610136Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:08.610140Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01_OOGE"::Berlin::0
2023-01-26T16:06:08.610142Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcode_01_OOGE.json"
2023-01-26T16:06:08.610145Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:08.610147Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:08.610317Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcode_01_OOGE"
2023-01-26T16:06:08.610322Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-26T16:06:08.610329Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:08.610332Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01_OOGE"::London::0
2023-01-26T16:06:08.610334Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcode_01_OOGE.json"
2023-01-26T16:06:08.610337Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:08.610338Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:08.610494Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcode_01_OOGE"
2023-01-26T16:06:08.610499Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-26T16:06:08.610505Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:08.610507Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01_OOGE"::Merge::0
2023-01-26T16:06:08.610509Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcode_01_OOGE.json"
2023-01-26T16:06:08.610511Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:08.610513Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:08.610671Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcode_01_OOGE"
2023-01-26T16:06:08.610676Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-26T16:06:08.612121Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:366.431563ms
2023-01-26T16:06:08.903898Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcode_01_SuicideEnd.json", Total Files :: 1
2023-01-26T16:06:08.933668Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:08.933809Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:08.933813Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:08.933883Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:08.933886Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:08.933970Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:08.933973Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:08.934051Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:08.934146Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:08.934149Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01_SuicideEnd"::Istanbul::0
2023-01-26T16:06:08.934153Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcode_01_SuicideEnd.json"
2023-01-26T16:06:08.934156Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:08.934158Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:09.298810Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcode_01_SuicideEnd"
2023-01-26T16:06:09.298828Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-26T16:06:09.298841Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:09.298846Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01_SuicideEnd"::Berlin::0
2023-01-26T16:06:09.298848Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcode_01_SuicideEnd.json"
2023-01-26T16:06:09.298853Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:09.298854Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:09.298994Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcode_01_SuicideEnd"
2023-01-26T16:06:09.298999Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-26T16:06:09.299005Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:09.299007Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01_SuicideEnd"::London::0
2023-01-26T16:06:09.299010Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcode_01_SuicideEnd.json"
2023-01-26T16:06:09.299013Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:09.299015Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:09.299142Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcode_01_SuicideEnd"
2023-01-26T16:06:09.299147Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-26T16:06:09.299153Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:09.299156Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcode_01_SuicideEnd"::Merge::0
2023-01-26T16:06:09.299158Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcode_01_SuicideEnd.json"
2023-01-26T16:06:09.299161Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:09.299163Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:09.299291Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcode_01_SuicideEnd"
2023-01-26T16:06:09.299296Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-26T16:06:09.301292Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:365.638124ms
2023-01-26T16:06:09.564180Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecall_010.json", Total Files :: 1
2023-01-26T16:06:09.593104Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:09.593237Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:09.593241Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:09.593292Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:09.593294Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:09.593354Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:09.593356Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:09.593410Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:09.593412Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:09.593462Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:09.593538Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:09.593541Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010"::Istanbul::0
2023-01-26T16:06:09.593544Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecall_010.json"
2023-01-26T16:06:09.593548Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:09.593549Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:09.992772Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010"
2023-01-26T16:06:09.992789Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-26T16:06:09.992801Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:09.992805Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010"::Berlin::0
2023-01-26T16:06:09.992806Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecall_010.json"
2023-01-26T16:06:09.992810Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:09.992811Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:09.992938Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010"
2023-01-26T16:06:09.992943Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-26T16:06:09.992950Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:09.992953Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010"::London::0
2023-01-26T16:06:09.992955Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecall_010.json"
2023-01-26T16:06:09.992959Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:09.992960Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:09.993093Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010"
2023-01-26T16:06:09.993098Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-26T16:06:09.993104Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:09.993106Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010"::Merge::0
2023-01-26T16:06:09.993108Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecall_010.json"
2023-01-26T16:06:09.993111Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:09.993112Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:09.993253Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010"
2023-01-26T16:06:09.993257Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-26T16:06:09.994967Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:400.163406ms
2023-01-26T16:06:10.256859Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecall_010_OOGE.json", Total Files :: 1
2023-01-26T16:06:10.287229Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:10.287368Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:10.287371Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:10.287424Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:10.287427Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:10.287487Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:10.287489Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:10.287546Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:10.287548Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:10.287601Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:10.287674Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:10.287677Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_OOGE"::Istanbul::0
2023-01-26T16:06:10.287680Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecall_010_OOGE.json"
2023-01-26T16:06:10.287684Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:10.287685Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:10.650841Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_OOGE"
2023-01-26T16:06:10.650854Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-26T16:06:10.650865Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:10.650869Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_OOGE"::Berlin::0
2023-01-26T16:06:10.650871Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecall_010_OOGE.json"
2023-01-26T16:06:10.650874Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:10.650876Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:10.651049Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_OOGE"
2023-01-26T16:06:10.651053Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-26T16:06:10.651060Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:10.651062Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_OOGE"::London::0
2023-01-26T16:06:10.651064Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecall_010_OOGE.json"
2023-01-26T16:06:10.651066Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:10.651068Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:10.651230Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_OOGE"
2023-01-26T16:06:10.651234Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-26T16:06:10.651240Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:10.651243Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_OOGE"::Merge::0
2023-01-26T16:06:10.651244Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecall_010_OOGE.json"
2023-01-26T16:06:10.651247Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:10.651249Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:10.651410Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_OOGE"
2023-01-26T16:06:10.651415Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-26T16:06:10.653086Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:364.198008ms
2023-01-26T16:06:10.924506Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecall_010_OOGMAfter.json", Total Files :: 1
2023-01-26T16:06:10.953433Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:10.953648Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:10.953653Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:10.953704Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:10.953706Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:10.953763Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:10.953765Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:10.953820Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:10.953823Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:10.953874Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:10.953945Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:10.953948Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_OOGMAfter"::Istanbul::0
2023-01-26T16:06:10.953951Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecall_010_OOGMAfter.json"
2023-01-26T16:06:10.953955Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:10.953956Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:11.319644Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_OOGMAfter"
2023-01-26T16:06:11.319658Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3457188,
    events_root: None,
}
2023-01-26T16:06:11.319669Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:11.319673Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_OOGMAfter"::Berlin::0
2023-01-26T16:06:11.319675Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecall_010_OOGMAfter.json"
2023-01-26T16:06:11.319678Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:11.319680Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:11.319852Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_OOGMAfter"
2023-01-26T16:06:11.319856Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2558154,
    events_root: None,
}
2023-01-26T16:06:11.319862Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:11.319864Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_OOGMAfter"::London::0
2023-01-26T16:06:11.319866Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecall_010_OOGMAfter.json"
2023-01-26T16:06:11.319869Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:11.319870Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:11.320026Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_OOGMAfter"
2023-01-26T16:06:11.320031Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2558154,
    events_root: None,
}
2023-01-26T16:06:11.320036Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:11.320038Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_OOGMAfter"::Merge::0
2023-01-26T16:06:11.320040Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecall_010_OOGMAfter.json"
2023-01-26T16:06:11.320043Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:11.320045Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:11.320199Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_OOGMAfter"
2023-01-26T16:06:11.320203Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2558154,
    events_root: None,
}
2023-01-26T16:06:11.321886Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:366.781181ms
2023-01-26T16:06:11.586257Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecall_010_OOGMBefore.json", Total Files :: 1
2023-01-26T16:06:11.616758Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:11.616900Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:11.616904Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:11.616957Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:11.616960Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:11.617019Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:11.617022Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:11.617082Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:11.617084Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:11.617138Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:11.617212Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:11.617216Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_OOGMBefore"::Istanbul::0
2023-01-26T16:06:11.617218Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecall_010_OOGMBefore.json"
2023-01-26T16:06:11.617222Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:11.617223Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:11.990298Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_OOGMBefore"
2023-01-26T16:06:11.990314Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-26T16:06:11.990325Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:11.990329Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_OOGMBefore"::Berlin::0
2023-01-26T16:06:11.990331Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecall_010_OOGMBefore.json"
2023-01-26T16:06:11.990334Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:11.990335Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:11.990515Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_OOGMBefore"
2023-01-26T16:06:11.990520Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-26T16:06:11.990526Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:11.990528Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_OOGMBefore"::London::0
2023-01-26T16:06:11.990530Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecall_010_OOGMBefore.json"
2023-01-26T16:06:11.990533Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:11.990534Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:11.990703Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_OOGMBefore"
2023-01-26T16:06:11.990707Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-26T16:06:11.990714Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:11.990717Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_OOGMBefore"::Merge::0
2023-01-26T16:06:11.990719Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecall_010_OOGMBefore.json"
2023-01-26T16:06:11.990723Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:11.990724Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:11.990889Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_OOGMBefore"
2023-01-26T16:06:11.990893Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-26T16:06:11.992590Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:374.145288ms
2023-01-26T16:06:12.267550Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecall_010_SuicideEnd.json", Total Files :: 1
2023-01-26T16:06:12.296619Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:12.296785Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:12.296790Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:12.296846Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:12.296849Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:12.296911Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:12.296913Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:12.296970Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:12.296972Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:12.297031Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:12.297118Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:12.297123Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_SuicideEnd"::Istanbul::0
2023-01-26T16:06:12.297126Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecall_010_SuicideEnd.json"
2023-01-26T16:06:12.297131Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:12.297133Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:12.683882Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_SuicideEnd"
2023-01-26T16:06:12.683897Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-26T16:06:12.683909Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:12.683913Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_SuicideEnd"::Berlin::0
2023-01-26T16:06:12.683915Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecall_010_SuicideEnd.json"
2023-01-26T16:06:12.683919Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:12.683920Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:12.684043Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_SuicideEnd"
2023-01-26T16:06:12.684048Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-26T16:06:12.684054Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:12.684057Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_SuicideEnd"::London::0
2023-01-26T16:06:12.684059Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecall_010_SuicideEnd.json"
2023-01-26T16:06:12.684063Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:12.684065Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:12.684175Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_SuicideEnd"
2023-01-26T16:06:12.684179Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-26T16:06:12.684185Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:12.684187Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_SuicideEnd"::Merge::0
2023-01-26T16:06:12.684189Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecall_010_SuicideEnd.json"
2023-01-26T16:06:12.684192Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:12.684193Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:12.684305Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_SuicideEnd"
2023-01-26T16:06:12.684309Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-26T16:06:12.685993Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:387.702345ms
2023-01-26T16:06:12.968311Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecall_010_SuicideMiddle.json", Total Files :: 1
2023-01-26T16:06:12.998290Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:12.998431Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:12.998434Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:12.998488Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:12.998490Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:12.998550Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:12.998552Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:12.998610Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:12.998612Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:12.998666Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:12.998740Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:12.998743Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_SuicideMiddle"::Istanbul::0
2023-01-26T16:06:12.998746Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecall_010_SuicideMiddle.json"
2023-01-26T16:06:12.998750Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:12.998751Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:13.348039Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_SuicideMiddle"
2023-01-26T16:06:13.348054Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-26T16:06:13.348068Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:13.348071Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_SuicideMiddle"::Berlin::0
2023-01-26T16:06:13.348073Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecall_010_SuicideMiddle.json"
2023-01-26T16:06:13.348077Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:13.348078Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:13.348204Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_SuicideMiddle"
2023-01-26T16:06:13.348208Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-26T16:06:13.348215Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:13.348217Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_SuicideMiddle"::London::0
2023-01-26T16:06:13.348219Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecall_010_SuicideMiddle.json"
2023-01-26T16:06:13.348222Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:13.348223Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:13.348359Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_SuicideMiddle"
2023-01-26T16:06:13.348365Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-26T16:06:13.348372Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:13.348374Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_010_SuicideMiddle"::Merge::0
2023-01-26T16:06:13.348376Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecall_010_SuicideMiddle.json"
2023-01-26T16:06:13.348378Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:13.348380Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:13.348494Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_010_SuicideMiddle"
2023-01-26T16:06:13.348498Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-26T16:06:13.350200Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:350.219096ms
2023-01-26T16:06:13.618799Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecall_ABCB_RECURSIVE.json", Total Files :: 1
2023-01-26T16:06:13.649816Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:13.649958Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:13.649962Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:13.650017Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:13.650019Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:13.650081Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:13.650084Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:13.650141Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:13.650215Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:13.650219Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_ABCB_RECURSIVE"::Istanbul::0
2023-01-26T16:06:13.650221Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecall_ABCB_RECURSIVE.json"
2023-01-26T16:06:13.650226Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:13.650227Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:14.007781Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_ABCB_RECURSIVE"
2023-01-26T16:06:14.007796Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6073274,
    events_root: None,
}
2023-01-26T16:06:14.007816Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:14.007820Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_ABCB_RECURSIVE"::Berlin::0
2023-01-26T16:06:14.007822Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecall_ABCB_RECURSIVE.json"
2023-01-26T16:06:14.007825Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:14.007827Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:14.008170Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_ABCB_RECURSIVE"
2023-01-26T16:06:14.008175Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5173496,
    events_root: None,
}
2023-01-26T16:06:14.008188Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:14.008191Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_ABCB_RECURSIVE"::London::0
2023-01-26T16:06:14.008193Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecall_ABCB_RECURSIVE.json"
2023-01-26T16:06:14.008197Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:14.008198Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:14.008526Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_ABCB_RECURSIVE"
2023-01-26T16:06:14.008531Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5173496,
    events_root: None,
}
2023-01-26T16:06:14.008545Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:14.008547Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecall_ABCB_RECURSIVE"::Merge::0
2023-01-26T16:06:14.008549Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecall_ABCB_RECURSIVE.json"
2023-01-26T16:06:14.008552Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:14.008553Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:14.008874Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecall_ABCB_RECURSIVE"
2023-01-26T16:06:14.008879Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5173496,
    events_root: None,
}
2023-01-26T16:06:14.010664Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:359.081888ms
2023-01-26T16:06:14.283050Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_011.json", Total Files :: 1
2023-01-26T16:06:14.312375Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:14.312508Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:14.312512Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:14.312562Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:14.312564Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:14.312621Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:14.312623Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:14.312678Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:14.312680Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:14.312731Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:14.312802Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:14.312805Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011"::Istanbul::0
2023-01-26T16:06:14.312808Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_011.json"
2023-01-26T16:06:14.312811Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:14.312813Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:14.687712Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011"
2023-01-26T16:06:14.687727Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-26T16:06:14.687739Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:14.687742Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011"::Berlin::0
2023-01-26T16:06:14.687744Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_011.json"
2023-01-26T16:06:14.687747Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:14.687749Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:14.687873Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011"
2023-01-26T16:06:14.687878Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-26T16:06:14.687884Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:14.687886Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011"::London::0
2023-01-26T16:06:14.687888Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_011.json"
2023-01-26T16:06:14.687891Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:14.687892Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:14.688004Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011"
2023-01-26T16:06:14.688009Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-26T16:06:14.688015Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:14.688017Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011"::Merge::0
2023-01-26T16:06:14.688019Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_011.json"
2023-01-26T16:06:14.688022Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:14.688023Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:14.688151Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011"
2023-01-26T16:06:14.688156Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2078015,
    events_root: None,
}
2023-01-26T16:06:14.689751Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:375.790989ms
2023-01-26T16:06:14.947571Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_011_OOGE.json", Total Files :: 1
2023-01-26T16:06:14.976649Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:14.976790Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:14.976795Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:14.976851Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:14.976854Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:14.976915Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:14.976919Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:14.976982Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:14.976986Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:14.977041Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:14.977115Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:14.977119Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_OOGE"::Istanbul::0
2023-01-26T16:06:14.977122Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_011_OOGE.json"
2023-01-26T16:06:14.977127Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:14.977129Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:15.348883Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_OOGE"
2023-01-26T16:06:15.348899Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-26T16:06:15.348910Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:15.348915Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_OOGE"::Berlin::0
2023-01-26T16:06:15.348918Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_011_OOGE.json"
2023-01-26T16:06:15.348921Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:15.348923Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:15.349101Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_OOGE"
2023-01-26T16:06:15.349105Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-26T16:06:15.349112Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:15.349114Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_OOGE"::London::0
2023-01-26T16:06:15.349116Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_011_OOGE.json"
2023-01-26T16:06:15.349119Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:15.349120Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:15.349282Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_OOGE"
2023-01-26T16:06:15.349288Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-26T16:06:15.349294Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:15.349296Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_OOGE"::Merge::0
2023-01-26T16:06:15.349298Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_011_OOGE.json"
2023-01-26T16:06:15.349301Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:15.349302Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:15.349463Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_OOGE"
2023-01-26T16:06:15.349476Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-26T16:06:15.351107Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:372.837953ms
2023-01-26T16:06:15.638004Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_011_OOGMAfter.json", Total Files :: 1
2023-01-26T16:06:15.667378Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:15.667522Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:15.667525Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:15.667580Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:15.667582Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:15.667642Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:15.667644Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:15.667701Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:15.667703Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:15.667755Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:15.667828Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:15.667831Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_OOGMAfter"::Istanbul::0
2023-01-26T16:06:15.667834Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_011_OOGMAfter.json"
2023-01-26T16:06:15.667838Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:15.667839Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:16.038461Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_OOGMAfter"
2023-01-26T16:06:16.038477Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3457188,
    events_root: None,
}
2023-01-26T16:06:16.038489Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:16.038494Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_OOGMAfter"::Berlin::0
2023-01-26T16:06:16.038496Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_011_OOGMAfter.json"
2023-01-26T16:06:16.038500Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:16.038501Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:16.038686Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_OOGMAfter"
2023-01-26T16:06:16.038691Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2558154,
    events_root: None,
}
2023-01-26T16:06:16.038697Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:16.038699Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_OOGMAfter"::London::0
2023-01-26T16:06:16.038701Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_011_OOGMAfter.json"
2023-01-26T16:06:16.038704Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:16.038705Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:16.038871Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_OOGMAfter"
2023-01-26T16:06:16.038876Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2558154,
    events_root: None,
}
2023-01-26T16:06:16.038882Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:16.038884Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_OOGMAfter"::Merge::0
2023-01-26T16:06:16.038885Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_011_OOGMAfter.json"
2023-01-26T16:06:16.038888Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:16.038890Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:16.039095Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_OOGMAfter"
2023-01-26T16:06:16.039101Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2558154,
    events_root: None,
}
2023-01-26T16:06:16.041634Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:371.734262ms
2023-01-26T16:06:16.320688Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_011_OOGMBefore.json", Total Files :: 1
2023-01-26T16:06:16.350663Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:16.350834Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:16.350839Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:16.350909Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:16.350914Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:16.350989Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:16.350993Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:16.351067Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:16.351070Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:16.351137Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:16.351231Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:16.351236Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_OOGMBefore"::Istanbul::0
2023-01-26T16:06:16.351240Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_011_OOGMBefore.json"
2023-01-26T16:06:16.351244Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:16.351246Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:16.700498Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_OOGMBefore"
2023-01-26T16:06:16.700514Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-26T16:06:16.700526Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:16.700530Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_OOGMBefore"::Berlin::0
2023-01-26T16:06:16.700532Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_011_OOGMBefore.json"
2023-01-26T16:06:16.700536Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:16.700538Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:16.700708Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_OOGMBefore"
2023-01-26T16:06:16.700713Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-26T16:06:16.700719Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:16.700721Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_OOGMBefore"::London::0
2023-01-26T16:06:16.700723Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_011_OOGMBefore.json"
2023-01-26T16:06:16.700726Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:16.700727Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:16.700898Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_OOGMBefore"
2023-01-26T16:06:16.700904Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-26T16:06:16.700910Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:16.700912Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_OOGMBefore"::Merge::0
2023-01-26T16:06:16.700914Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_011_OOGMBefore.json"
2023-01-26T16:06:16.700917Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:16.700918Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:16.701075Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_OOGMBefore"
2023-01-26T16:06:16.701080Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2522575,
    events_root: None,
}
2023-01-26T16:06:16.703251Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:350.428109ms
2023-01-26T16:06:16.990983Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_011_SuicideEnd.json", Total Files :: 1
2023-01-26T16:06:17.021023Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:17.021159Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:17.021162Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:17.021215Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:17.021217Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:17.021274Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:17.021276Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:17.021333Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:17.021335Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:17.021388Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:17.021459Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:17.021463Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_SuicideEnd"::Istanbul::0
2023-01-26T16:06:17.021466Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_011_SuicideEnd.json"
2023-01-26T16:06:17.021480Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:17.021482Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:17.397075Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_SuicideEnd"
2023-01-26T16:06:17.397092Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-26T16:06:17.397105Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:17.397109Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_SuicideEnd"::Berlin::0
2023-01-26T16:06:17.397111Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_011_SuicideEnd.json"
2023-01-26T16:06:17.397115Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:17.397117Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:17.397258Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_SuicideEnd"
2023-01-26T16:06:17.397263Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-26T16:06:17.397269Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:17.397271Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_SuicideEnd"::London::0
2023-01-26T16:06:17.397272Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_011_SuicideEnd.json"
2023-01-26T16:06:17.397275Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:17.397277Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:17.397394Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_SuicideEnd"
2023-01-26T16:06:17.397399Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-26T16:06:17.397404Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:17.397407Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_SuicideEnd"::Merge::0
2023-01-26T16:06:17.397408Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_011_SuicideEnd.json"
2023-01-26T16:06:17.397411Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:17.397413Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:17.397566Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_SuicideEnd"
2023-01-26T16:06:17.397571Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-26T16:06:17.399359Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:376.558753ms
2023-01-26T16:06:17.669579Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_011_SuicideMiddle.json", Total Files :: 1
2023-01-26T16:06:17.698334Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:17.698472Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:17.698476Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:17.698528Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:17.698530Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:17.698588Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:17.698590Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:17.698645Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:17.698648Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:17.698699Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:17.698770Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:17.698773Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_SuicideMiddle"::Istanbul::0
2023-01-26T16:06:17.698776Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_011_SuicideMiddle.json"
2023-01-26T16:06:17.698780Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:17.698782Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:18.067369Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_SuicideMiddle"
2023-01-26T16:06:18.067383Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-26T16:06:18.067395Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:18.067399Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_SuicideMiddle"::Berlin::0
2023-01-26T16:06:18.067401Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_011_SuicideMiddle.json"
2023-01-26T16:06:18.067405Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:18.067406Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:18.067534Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_SuicideMiddle"
2023-01-26T16:06:18.067538Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-26T16:06:18.067545Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:18.067547Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_SuicideMiddle"::London::0
2023-01-26T16:06:18.067549Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_011_SuicideMiddle.json"
2023-01-26T16:06:18.067552Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:18.067553Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:18.067690Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_SuicideMiddle"
2023-01-26T16:06:18.067695Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-26T16:06:18.067701Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:18.067704Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_011_SuicideMiddle"::Merge::0
2023-01-26T16:06:18.067706Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_011_SuicideMiddle.json"
2023-01-26T16:06:18.067709Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:18.067710Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:18.067850Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_011_SuicideMiddle"
2023-01-26T16:06:18.067855Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1872575,
    events_root: None,
}
2023-01-26T16:06:18.069403Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:369.530632ms
2023-01-26T16:06:18.335714Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_ABCB_RECURSIVE.json", Total Files :: 1
2023-01-26T16:06:18.369398Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:18.369549Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:18.369554Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:18.369606Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:18.369608Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:18.369667Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:18.369669Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:18.369724Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:18.369795Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:18.369798Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_ABCB_RECURSIVE"::Istanbul::0
2023-01-26T16:06:18.369801Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_ABCB_RECURSIVE.json"
2023-01-26T16:06:18.369805Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:18.369807Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:18.739469Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_ABCB_RECURSIVE"
2023-01-26T16:06:18.739482Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6073274,
    events_root: None,
}
2023-01-26T16:06:18.739496Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:18.739500Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_ABCB_RECURSIVE"::Berlin::0
2023-01-26T16:06:18.739502Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_ABCB_RECURSIVE.json"
2023-01-26T16:06:18.739505Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:18.739507Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:18.739836Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_ABCB_RECURSIVE"
2023-01-26T16:06:18.739840Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5173496,
    events_root: None,
}
2023-01-26T16:06:18.739854Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:18.739856Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_ABCB_RECURSIVE"::London::0
2023-01-26T16:06:18.739858Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_ABCB_RECURSIVE.json"
2023-01-26T16:06:18.739861Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:18.739862Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:18.740181Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_ABCB_RECURSIVE"
2023-01-26T16:06:18.740185Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5173496,
    events_root: None,
}
2023-01-26T16:06:18.740197Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:18.740200Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcallcodecallcode_ABCB_RECURSIVE"::Merge::0
2023-01-26T16:06:18.740201Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcallcodecallcode_ABCB_RECURSIVE.json"
2023-01-26T16:06:18.740204Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:18.740206Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:18.740519Z  INFO evm_eth_compliance::statetest::runner: UC : "callcallcodecallcode_ABCB_RECURSIVE"
2023-01-26T16:06:18.740524Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5173496,
    events_root: None,
}
2023-01-26T16:06:18.742281Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:371.14352ms
2023-01-26T16:06:19.023267Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecall_10.json", Total Files :: 1
2023-01-26T16:06:19.053551Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:19.053731Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:19.053748Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:19.053826Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:19.053836Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:19.053921Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:19.053925Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:19.053999Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:19.054094Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:19.054098Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10"::Istanbul::0
2023-01-26T16:06:19.054101Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecall_10.json"
2023-01-26T16:06:19.054105Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:19.054107Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:19.408096Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecall_10"
2023-01-26T16:06:19.408162Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:06:19.408187Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:19.408194Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10"::Berlin::0
2023-01-26T16:06:19.408197Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecall_10.json"
2023-01-26T16:06:19.408201Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:19.408203Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:19.408531Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecall_10"
2023-01-26T16:06:19.408548Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:06:19.408559Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:19.408563Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10"::London::0
2023-01-26T16:06:19.408565Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecall_10.json"
2023-01-26T16:06:19.408568Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:19.408570Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:19.408817Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecall_10"
2023-01-26T16:06:19.408835Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:06:19.408844Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:19.408847Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10"::Merge::0
2023-01-26T16:06:19.408849Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecall_10.json"
2023-01-26T16:06:19.408853Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:19.408855Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:19.409086Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecall_10"
2023-01-26T16:06:19.409092Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:06:19.411630Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:355.553765ms
2023-01-26T16:06:19.699298Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecall_10_OOGE.json", Total Files :: 1
2023-01-26T16:06:19.727371Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:19.727505Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:19.727508Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:19.727558Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:19.727561Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:19.727618Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:19.727620Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:19.727674Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:19.727743Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:19.727746Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10_OOGE"::Istanbul::0
2023-01-26T16:06:19.727749Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecall_10_OOGE.json"
2023-01-26T16:06:19.727752Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:19.727754Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:20.109070Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecall_10_OOGE"
2023-01-26T16:06:20.109084Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:20.109098Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:20.109102Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10_OOGE"::Berlin::0
2023-01-26T16:06:20.109104Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecall_10_OOGE.json"
2023-01-26T16:06:20.109107Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:20.109109Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:20.109338Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecall_10_OOGE"
2023-01-26T16:06:20.109344Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:20.109354Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:20.109356Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10_OOGE"::London::0
2023-01-26T16:06:20.109358Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecall_10_OOGE.json"
2023-01-26T16:06:20.109360Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:20.109362Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:20.109618Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecall_10_OOGE"
2023-01-26T16:06:20.109624Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:20.109637Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:20.109640Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10_OOGE"::Merge::0
2023-01-26T16:06:20.109642Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecall_10_OOGE.json"
2023-01-26T16:06:20.109645Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:20.109646Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:20.109910Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecall_10_OOGE"
2023-01-26T16:06:20.109915Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:20.111600Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:382.557312ms
2023-01-26T16:06:20.388035Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecall_10_SuicideEnd.json", Total Files :: 1
2023-01-26T16:06:20.418022Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:20.418162Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:20.418165Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:20.418221Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:20.418223Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:20.418285Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:20.418287Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:20.418343Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:20.418415Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:20.418417Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10_SuicideEnd"::Istanbul::0
2023-01-26T16:06:20.418420Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecall_10_SuicideEnd.json"
2023-01-26T16:06:20.418423Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:20.418425Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:20.790634Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecall_10_SuicideEnd"
2023-01-26T16:06:20.790645Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:20.790657Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:20.790661Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10_SuicideEnd"::Berlin::0
2023-01-26T16:06:20.790663Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecall_10_SuicideEnd.json"
2023-01-26T16:06:20.790667Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:20.790668Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:20.790856Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecall_10_SuicideEnd"
2023-01-26T16:06:20.790860Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:20.790867Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:20.790869Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10_SuicideEnd"::London::0
2023-01-26T16:06:20.790871Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecall_10_SuicideEnd.json"
2023-01-26T16:06:20.790874Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:20.790876Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:20.791057Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecall_10_SuicideEnd"
2023-01-26T16:06:20.791063Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:20.791070Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:20.791072Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecall_10_SuicideEnd"::Merge::0
2023-01-26T16:06:20.791074Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecall_10_SuicideEnd.json"
2023-01-26T16:06:20.791077Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:20.791078Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:20.791255Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecall_10_SuicideEnd"
2023-01-26T16:06:20.791260Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:20.792956Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:373.249098ms
2023-01-26T16:06:21.067334Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcall_100.json", Total Files :: 1
2023-01-26T16:06:21.097033Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:21.097171Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:21.097175Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:21.097227Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:21.097229Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:21.097299Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:21.097303Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:21.097393Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:21.097398Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:21.097515Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:21.097616Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:21.097619Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100"::Istanbul::0
2023-01-26T16:06:21.097623Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcall_100.json"
2023-01-26T16:06:21.097627Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:21.097629Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:21.464514Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100"
2023-01-26T16:06:21.464531Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:06:21.464545Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:21.464550Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100"::Berlin::0
2023-01-26T16:06:21.464552Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcall_100.json"
2023-01-26T16:06:21.464555Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:21.464557Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:21.464743Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100"
2023-01-26T16:06:21.464747Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:06:21.464754Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:21.464757Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100"::London::0
2023-01-26T16:06:21.464759Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcall_100.json"
2023-01-26T16:06:21.464762Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:21.464763Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:21.464937Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100"
2023-01-26T16:06:21.464942Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:06:21.464949Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:21.464951Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100"::Merge::0
2023-01-26T16:06:21.464952Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcall_100.json"
2023-01-26T16:06:21.464955Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:21.464956Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:21.465128Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100"
2023-01-26T16:06:21.465133Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:06:21.466908Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:368.110527ms
2023-01-26T16:06:21.738145Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcall_100_OOGE.json", Total Files :: 1
2023-01-26T16:06:21.767132Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:21.767263Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:21.767267Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:21.767318Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:21.767320Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:21.767378Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:21.767380Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:21.767436Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:21.767438Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:21.767490Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:21.767561Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:21.767564Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_OOGE"::Istanbul::0
2023-01-26T16:06:21.767567Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcall_100_OOGE.json"
2023-01-26T16:06:21.767570Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:21.767572Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:22.127646Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_OOGE"
2023-01-26T16:06:22.127660Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:22.127673Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:22.127677Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_OOGE"::Berlin::0
2023-01-26T16:06:22.127678Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcall_100_OOGE.json"
2023-01-26T16:06:22.127683Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:22.127684Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:22.127935Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_OOGE"
2023-01-26T16:06:22.127941Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:22.127950Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:22.127952Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_OOGE"::London::0
2023-01-26T16:06:22.127954Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcall_100_OOGE.json"
2023-01-26T16:06:22.127956Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:22.127958Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:22.128187Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_OOGE"
2023-01-26T16:06:22.128193Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:22.128200Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:22.128203Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_OOGE"::Merge::0
2023-01-26T16:06:22.128204Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcall_100_OOGE.json"
2023-01-26T16:06:22.128207Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:22.128209Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:22.128442Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_OOGE"
2023-01-26T16:06:22.128447Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:22.130548Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:361.327053ms
2023-01-26T16:06:22.410561Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcall_100_OOGMAfter.json", Total Files :: 1
2023-01-26T16:06:22.440102Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:22.440239Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:22.440242Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:22.440295Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:22.440297Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:22.440355Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:22.440357Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:22.440413Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:22.440415Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:22.440466Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:22.440540Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:22.440542Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_OOGMAfter"::Istanbul::0
2023-01-26T16:06:22.440545Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcall_100_OOGMAfter.json"
2023-01-26T16:06:22.440549Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:22.440550Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:22.799767Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_OOGMAfter"
2023-01-26T16:06:22.799779Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4331310,
    events_root: None,
}
2023-01-26T16:06:22.799792Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:22.799796Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_OOGMAfter"::Berlin::0
2023-01-26T16:06:22.799797Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcall_100_OOGMAfter.json"
2023-01-26T16:06:22.799801Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:22.799803Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:22.800052Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_OOGMAfter"
2023-01-26T16:06:22.800058Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3433996,
    events_root: None,
}
2023-01-26T16:06:22.800065Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:22.800067Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_OOGMAfter"::London::0
2023-01-26T16:06:22.800069Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcall_100_OOGMAfter.json"
2023-01-26T16:06:22.800072Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:22.800073Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:22.800350Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_OOGMAfter"
2023-01-26T16:06:22.800355Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3433996,
    events_root: None,
}
2023-01-26T16:06:22.800363Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:22.800365Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_OOGMAfter"::Merge::0
2023-01-26T16:06:22.800367Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcall_100_OOGMAfter.json"
2023-01-26T16:06:22.800370Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:22.800371Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:22.800612Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_OOGMAfter"
2023-01-26T16:06:22.800616Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3433996,
    events_root: None,
}
2023-01-26T16:06:22.802437Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:360.526014ms
2023-01-26T16:06:23.095779Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcall_100_OOGMBefore.json", Total Files :: 1
2023-01-26T16:06:23.125325Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:23.125462Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:23.125466Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:23.125530Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:23.125532Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:23.125593Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:23.125595Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:23.125652Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:23.125655Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:23.125708Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:23.125781Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:23.125784Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_OOGMBefore"::Istanbul::0
2023-01-26T16:06:23.125787Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcall_100_OOGMBefore.json"
2023-01-26T16:06:23.125791Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:23.125792Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:23.500242Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_OOGMBefore"
2023-01-26T16:06:23.500257Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:23.500269Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:23.500273Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_OOGMBefore"::Berlin::0
2023-01-26T16:06:23.500275Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcall_100_OOGMBefore.json"
2023-01-26T16:06:23.500279Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:23.500280Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:23.500531Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_OOGMBefore"
2023-01-26T16:06:23.500537Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:23.500544Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:23.500546Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_OOGMBefore"::London::0
2023-01-26T16:06:23.500548Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcall_100_OOGMBefore.json"
2023-01-26T16:06:23.500551Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:23.500552Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:23.500783Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_OOGMBefore"
2023-01-26T16:06:23.500788Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:23.500795Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:23.500798Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_OOGMBefore"::Merge::0
2023-01-26T16:06:23.500800Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcall_100_OOGMBefore.json"
2023-01-26T16:06:23.500804Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:23.500805Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:23.501031Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_OOGMBefore"
2023-01-26T16:06:23.501036Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:23.502932Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:375.723307ms
2023-01-26T16:06:23.774997Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcall_100_SuicideEnd.json", Total Files :: 1
2023-01-26T16:06:23.805508Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:23.805653Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:23.805657Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:23.805712Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:23.805715Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:23.805778Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:23.805780Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:23.805839Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:23.805841Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:23.805897Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:23.805972Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:23.805975Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_SuicideEnd"::Istanbul::0
2023-01-26T16:06:23.805979Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcall_100_SuicideEnd.json"
2023-01-26T16:06:23.805982Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:23.805984Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:24.209021Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_SuicideEnd"
2023-01-26T16:06:24.209037Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:24.209055Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:24.209060Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_SuicideEnd"::Berlin::0
2023-01-26T16:06:24.209062Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcall_100_SuicideEnd.json"
2023-01-26T16:06:24.209066Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:24.209068Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:24.209262Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_SuicideEnd"
2023-01-26T16:06:24.209267Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:24.209275Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:24.209277Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_SuicideEnd"::London::0
2023-01-26T16:06:24.209279Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcall_100_SuicideEnd.json"
2023-01-26T16:06:24.209282Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:24.209284Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:24.209460Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_SuicideEnd"
2023-01-26T16:06:24.209464Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:24.209486Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:24.209489Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_SuicideEnd"::Merge::0
2023-01-26T16:06:24.209490Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcall_100_SuicideEnd.json"
2023-01-26T16:06:24.209493Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:24.209495Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:24.209672Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_SuicideEnd"
2023-01-26T16:06:24.209676Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:24.211594Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:404.182468ms
2023-01-26T16:06:24.477652Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcall_100_SuicideMiddle.json", Total Files :: 1
2023-01-26T16:06:24.508035Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:24.508176Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:24.508180Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:24.508235Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:24.508237Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:24.508299Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:24.508301Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:24.508358Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:24.508360Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:24.508413Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:24.508486Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:24.508489Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_SuicideMiddle"::Istanbul::0
2023-01-26T16:06:24.508492Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcall_100_SuicideMiddle.json"
2023-01-26T16:06:24.508496Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:24.508498Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:24.885423Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_SuicideMiddle"
2023-01-26T16:06:24.885438Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:24.885451Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:24.885455Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_SuicideMiddle"::Berlin::0
2023-01-26T16:06:24.885457Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcall_100_SuicideMiddle.json"
2023-01-26T16:06:24.885461Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:24.885462Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:24.885653Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_SuicideMiddle"
2023-01-26T16:06:24.885660Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:24.885666Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:24.885668Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_SuicideMiddle"::London::0
2023-01-26T16:06:24.885670Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcall_100_SuicideMiddle.json"
2023-01-26T16:06:24.885673Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:24.885674Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:24.885845Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_SuicideMiddle"
2023-01-26T16:06:24.885850Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:24.885856Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:24.885858Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_100_SuicideMiddle"::Merge::0
2023-01-26T16:06:24.885860Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcall_100_SuicideMiddle.json"
2023-01-26T16:06:24.885864Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:24.885865Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:24.886036Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_100_SuicideMiddle"
2023-01-26T16:06:24.886040Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:24.887900Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:378.016056ms
2023-01-26T16:06:25.156751Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcall_ABCB_RECURSIVE.json", Total Files :: 1
2023-01-26T16:06:25.186956Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:25.187100Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:25.187103Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:25.187159Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:25.187162Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:25.187224Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:25.187226Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:25.187283Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:25.187356Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:25.187359Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_ABCB_RECURSIVE"::Istanbul::0
2023-01-26T16:06:25.187362Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcall_ABCB_RECURSIVE.json"
2023-01-26T16:06:25.187366Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:25.187367Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:25.568562Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_ABCB_RECURSIVE"
2023-01-26T16:06:25.568578Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6108470,
    events_root: None,
}
2023-01-26T16:06:25.568592Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:25.568595Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_ABCB_RECURSIVE"::Berlin::0
2023-01-26T16:06:25.568597Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcall_ABCB_RECURSIVE.json"
2023-01-26T16:06:25.568601Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:25.568602Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:25.568949Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_ABCB_RECURSIVE"
2023-01-26T16:06:25.568955Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5227244,
    events_root: None,
}
2023-01-26T16:06:25.568963Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:25.568965Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_ABCB_RECURSIVE"::London::0
2023-01-26T16:06:25.568967Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcall_ABCB_RECURSIVE.json"
2023-01-26T16:06:25.568970Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:25.568971Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:25.569344Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_ABCB_RECURSIVE"
2023-01-26T16:06:25.569350Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5227244,
    events_root: None,
}
2023-01-26T16:06:25.569359Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:25.569361Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcall_ABCB_RECURSIVE"::Merge::0
2023-01-26T16:06:25.569363Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcall_ABCB_RECURSIVE.json"
2023-01-26T16:06:25.569366Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:25.569368Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:25.569720Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcall_ABCB_RECURSIVE"
2023-01-26T16:06:25.569725Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5227244,
    events_root: None,
}
2023-01-26T16:06:25.571281Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:382.781528ms
2023-01-26T16:06:25.850096Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101.json", Total Files :: 1
2023-01-26T16:06:25.879980Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:25.880124Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:25.880128Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:25.880185Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:25.880188Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:25.880250Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:25.880253Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:25.880320Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:25.880323Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:25.880380Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:25.880457Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:25.880461Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101"::Istanbul::0
2023-01-26T16:06:25.880465Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101.json"
2023-01-26T16:06:25.880470Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:25.880472Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:26.273603Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101"
2023-01-26T16:06:26.273617Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:06:26.273629Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:26.273633Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101"::Berlin::0
2023-01-26T16:06:26.273634Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101.json"
2023-01-26T16:06:26.273638Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:26.273639Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:26.273821Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101"
2023-01-26T16:06:26.273826Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:06:26.273832Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:26.273835Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101"::London::0
2023-01-26T16:06:26.273837Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101.json"
2023-01-26T16:06:26.273840Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:26.273841Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:26.274013Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101"
2023-01-26T16:06:26.274018Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:06:26.274024Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:26.274026Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101"::Merge::0
2023-01-26T16:06:26.274028Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101.json"
2023-01-26T16:06:26.274030Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:26.274032Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:26.274203Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101"
2023-01-26T16:06:26.274208Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:06:26.275742Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:394.239139ms
2023-01-26T16:06:26.550004Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101_OOGE.json", Total Files :: 1
2023-01-26T16:06:26.580061Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:26.580208Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:26.580212Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:26.580268Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:26.580271Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:26.580334Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:26.580337Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:26.580399Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:26.580403Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:26.580469Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:26.580564Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:26.580569Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_OOGE"::Istanbul::0
2023-01-26T16:06:26.580573Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101_OOGE.json"
2023-01-26T16:06:26.580578Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:26.580579Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:26.980377Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_OOGE"
2023-01-26T16:06:26.980399Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:26.980416Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:26.980421Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_OOGE"::Berlin::0
2023-01-26T16:06:26.980423Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101_OOGE.json"
2023-01-26T16:06:26.980426Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:26.980428Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:26.980671Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_OOGE"
2023-01-26T16:06:26.980676Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:26.980683Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:26.980685Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_OOGE"::London::0
2023-01-26T16:06:26.980687Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101_OOGE.json"
2023-01-26T16:06:26.980690Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:26.980691Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:26.980921Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_OOGE"
2023-01-26T16:06:26.980927Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:26.980934Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:26.980937Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_OOGE"::Merge::0
2023-01-26T16:06:26.980942Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101_OOGE.json"
2023-01-26T16:06:26.980945Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:26.980947Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:26.981191Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_OOGE"
2023-01-26T16:06:26.981195Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:26.983459Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:401.14649ms
2023-01-26T16:06:27.265274Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101_OOGMAfter.json", Total Files :: 1
2023-01-26T16:06:27.294522Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:27.294671Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:27.294675Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:27.294730Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:27.294732Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:27.294792Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:27.294794Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:27.294852Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:27.294855Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:27.294920Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:27.295020Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:27.295024Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_OOGMAfter"::Istanbul::0
2023-01-26T16:06:27.295027Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101_OOGMAfter.json"
2023-01-26T16:06:27.295030Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:27.295032Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:27.639078Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_OOGMAfter"
2023-01-26T16:06:27.639095Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4331310,
    events_root: None,
}
2023-01-26T16:06:27.639107Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:27.639111Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_OOGMAfter"::Berlin::0
2023-01-26T16:06:27.639113Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101_OOGMAfter.json"
2023-01-26T16:06:27.639116Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:27.639118Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:27.639360Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_OOGMAfter"
2023-01-26T16:06:27.639365Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3433996,
    events_root: None,
}
2023-01-26T16:06:27.639372Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:27.639375Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_OOGMAfter"::London::0
2023-01-26T16:06:27.639377Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101_OOGMAfter.json"
2023-01-26T16:06:27.639381Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:27.639382Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:27.639611Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_OOGMAfter"
2023-01-26T16:06:27.639615Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3433996,
    events_root: None,
}
2023-01-26T16:06:27.639622Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:27.639626Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_OOGMAfter"::Merge::0
2023-01-26T16:06:27.639628Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101_OOGMAfter.json"
2023-01-26T16:06:27.639631Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:27.639633Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:27.639861Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_OOGMAfter"
2023-01-26T16:06:27.639866Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3433996,
    events_root: None,
}
2023-01-26T16:06:27.641494Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:345.357946ms
2023-01-26T16:06:27.929375Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101_OOGMBefore.json", Total Files :: 1
2023-01-26T16:06:27.958535Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:27.958673Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:27.958677Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:27.958730Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:27.958732Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:27.958792Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:27.958794Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:27.958849Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:27.958851Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:27.958903Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:27.958978Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:27.958981Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_OOGMBefore"::Istanbul::0
2023-01-26T16:06:27.958984Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101_OOGMBefore.json"
2023-01-26T16:06:27.958987Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:27.958989Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:28.355988Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_OOGMBefore"
2023-01-26T16:06:28.356006Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:28.356022Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:28.356028Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_OOGMBefore"::Berlin::0
2023-01-26T16:06:28.356031Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101_OOGMBefore.json"
2023-01-26T16:06:28.356035Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:28.356037Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:28.356330Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_OOGMBefore"
2023-01-26T16:06:28.356336Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:28.356345Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:28.356348Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_OOGMBefore"::London::0
2023-01-26T16:06:28.356350Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101_OOGMBefore.json"
2023-01-26T16:06:28.356354Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:28.356356Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:28.356606Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_OOGMBefore"
2023-01-26T16:06:28.356612Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:28.356619Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:28.356621Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_OOGMBefore"::Merge::0
2023-01-26T16:06:28.356624Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101_OOGMBefore.json"
2023-01-26T16:06:28.356627Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:28.356628Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:28.356865Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_OOGMBefore"
2023-01-26T16:06:28.356870Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:28.358550Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:398.347061ms
2023-01-26T16:06:28.642392Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101_SuicideEnd.json", Total Files :: 1
2023-01-26T16:06:28.672004Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:28.672152Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:28.672156Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:28.672212Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:28.672214Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:28.672279Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:28.672283Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:28.672344Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:28.672347Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:28.672400Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:28.672480Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:28.672484Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_SuicideEnd"::Istanbul::0
2023-01-26T16:06:28.672487Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101_SuicideEnd.json"
2023-01-26T16:06:28.672490Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:28.672492Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:29.043794Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_SuicideEnd"
2023-01-26T16:06:29.043808Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:29.043822Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:29.043828Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_SuicideEnd"::Berlin::0
2023-01-26T16:06:29.043830Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101_SuicideEnd.json"
2023-01-26T16:06:29.043835Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:29.043837Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:29.044047Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_SuicideEnd"
2023-01-26T16:06:29.044054Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:29.044063Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:29.044066Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_SuicideEnd"::London::0
2023-01-26T16:06:29.044068Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101_SuicideEnd.json"
2023-01-26T16:06:29.044071Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:29.044073Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:29.044290Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_SuicideEnd"
2023-01-26T16:06:29.044296Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:29.044304Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:29.044309Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_SuicideEnd"::Merge::0
2023-01-26T16:06:29.044312Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101_SuicideEnd.json"
2023-01-26T16:06:29.044316Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:29.044318Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:29.044544Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_SuicideEnd"
2023-01-26T16:06:29.044550Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:29.046840Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:372.559362ms
2023-01-26T16:06:29.331778Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101_SuicideMiddle.json", Total Files :: 1
2023-01-26T16:06:29.362997Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:29.363158Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:29.363163Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:29.363222Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:29.363224Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:29.363289Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:29.363292Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:29.363351Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:29.363354Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:29.363412Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:29.363491Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:29.363495Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_SuicideMiddle"::Istanbul::0
2023-01-26T16:06:29.363500Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101_SuicideMiddle.json"
2023-01-26T16:06:29.363506Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:29.363508Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:29.708347Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_SuicideMiddle"
2023-01-26T16:06:29.708361Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:29.708377Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:29.708383Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_SuicideMiddle"::Berlin::0
2023-01-26T16:06:29.708385Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101_SuicideMiddle.json"
2023-01-26T16:06:29.708389Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:29.708391Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:29.708583Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_SuicideMiddle"
2023-01-26T16:06:29.708588Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:29.708596Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:29.708599Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_SuicideMiddle"::London::0
2023-01-26T16:06:29.708602Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101_SuicideMiddle.json"
2023-01-26T16:06:29.708606Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:29.708608Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:29.708784Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_SuicideMiddle"
2023-01-26T16:06:29.708789Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:29.708797Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:29.708802Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_101_SuicideMiddle"::Merge::0
2023-01-26T16:06:29.708805Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_101_SuicideMiddle.json"
2023-01-26T16:06:29.708809Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:29.708811Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:29.708983Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_101_SuicideMiddle"
2023-01-26T16:06:29.708988Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:29.711220Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:346.006478ms
2023-01-26T16:06:30.021528Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_ABCB_RECURSIVE.json", Total Files :: 1
2023-01-26T16:06:30.056027Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:30.056204Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:30.056209Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:30.056279Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:30.056283Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:30.056360Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:30.056363Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:30.056440Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:30.056539Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:30.056542Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_ABCB_RECURSIVE"::Istanbul::0
2023-01-26T16:06:30.056546Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_ABCB_RECURSIVE.json"
2023-01-26T16:06:30.056550Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:30.056554Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:30.433770Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_ABCB_RECURSIVE"
2023-01-26T16:06:30.433785Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6108470,
    events_root: None,
}
2023-01-26T16:06:30.433799Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:30.433803Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_ABCB_RECURSIVE"::Berlin::0
2023-01-26T16:06:30.433805Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_ABCB_RECURSIVE.json"
2023-01-26T16:06:30.433809Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:30.433810Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:30.434160Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_ABCB_RECURSIVE"
2023-01-26T16:06:30.434165Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5227244,
    events_root: None,
}
2023-01-26T16:06:30.434174Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:30.434176Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_ABCB_RECURSIVE"::London::0
2023-01-26T16:06:30.434179Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_ABCB_RECURSIVE.json"
2023-01-26T16:06:30.434182Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:30.434183Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:30.434525Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_ABCB_RECURSIVE"
2023-01-26T16:06:30.434530Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5227244,
    events_root: None,
}
2023-01-26T16:06:30.434538Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:30.434541Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcallcode_ABCB_RECURSIVE"::Merge::0
2023-01-26T16:06:30.434543Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcallcode_ABCB_RECURSIVE.json"
2023-01-26T16:06:30.434546Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:30.434547Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:30.434884Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcallcode_ABCB_RECURSIVE"
2023-01-26T16:06:30.434889Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 5227244,
    events_root: None,
}
2023-01-26T16:06:30.436610Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:378.875572ms
2023-01-26T16:06:30.719048Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcode_11.json", Total Files :: 1
2023-01-26T16:06:30.748126Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:30.748267Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:30.748271Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:30.748322Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:30.748324Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:30.748382Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:30.748384Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:30.748459Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:30.748569Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:30.748573Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11"::Istanbul::0
2023-01-26T16:06:30.748577Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcode_11.json"
2023-01-26T16:06:30.748581Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:30.748583Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:31.126898Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcode_11"
2023-01-26T16:06:31.126914Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:06:31.126926Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:31.126930Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11"::Berlin::0
2023-01-26T16:06:31.126933Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcode_11.json"
2023-01-26T16:06:31.126936Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:31.126937Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:31.127121Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcode_11"
2023-01-26T16:06:31.127126Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:06:31.127133Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:31.127135Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11"::London::0
2023-01-26T16:06:31.127137Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcode_11.json"
2023-01-26T16:06:31.127140Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:31.127141Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:31.127311Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcode_11"
2023-01-26T16:06:31.127316Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:06:31.127322Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:31.127324Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11"::Merge::0
2023-01-26T16:06:31.127326Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcode_11.json"
2023-01-26T16:06:31.127329Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:31.127332Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:31.127503Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcode_11"
2023-01-26T16:06:31.127507Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:06:31.129308Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:379.393826ms
2023-01-26T16:06:31.407070Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcode_11_OOGE.json", Total Files :: 1
2023-01-26T16:06:31.437641Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:31.437786Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:31.437790Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:31.437848Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:31.437850Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:31.437914Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:31.437917Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:31.437977Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:31.438053Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:31.438057Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11_OOGE"::Istanbul::0
2023-01-26T16:06:31.438061Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcode_11_OOGE.json"
2023-01-26T16:06:31.438066Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:31.438068Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:31.798791Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcode_11_OOGE"
2023-01-26T16:06:31.798808Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:31.798820Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:31.798824Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11_OOGE"::Berlin::0
2023-01-26T16:06:31.798826Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcode_11_OOGE.json"
2023-01-26T16:06:31.798830Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:31.798831Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:31.799065Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcode_11_OOGE"
2023-01-26T16:06:31.799070Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:31.799076Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:31.799078Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11_OOGE"::London::0
2023-01-26T16:06:31.799080Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcode_11_OOGE.json"
2023-01-26T16:06:31.799084Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:31.799085Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:31.799347Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcode_11_OOGE"
2023-01-26T16:06:31.799352Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:31.799360Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:31.799362Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11_OOGE"::Merge::0
2023-01-26T16:06:31.799364Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcode_11_OOGE.json"
2023-01-26T16:06:31.799366Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:31.799368Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:31.799592Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcode_11_OOGE"
2023-01-26T16:06:31.799598Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:31.801141Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:361.969357ms
2023-01-26T16:06:32.091736Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcode_11_SuicideEnd.json", Total Files :: 1
2023-01-26T16:06:32.121458Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:32.121620Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:32.121625Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:32.121685Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:32.121688Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:32.121751Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:32.121754Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:32.121814Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:32.121889Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:32.121892Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11_SuicideEnd"::Istanbul::0
2023-01-26T16:06:32.121896Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcode_11_SuicideEnd.json"
2023-01-26T16:06:32.121900Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:32.121903Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:32.471620Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcode_11_SuicideEnd"
2023-01-26T16:06:32.471637Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:32.471649Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:32.471653Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11_SuicideEnd"::Berlin::0
2023-01-26T16:06:32.471655Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcode_11_SuicideEnd.json"
2023-01-26T16:06:32.471658Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:32.471660Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:32.471849Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcode_11_SuicideEnd"
2023-01-26T16:06:32.471854Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:32.471860Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:32.471862Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11_SuicideEnd"::London::0
2023-01-26T16:06:32.471864Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcode_11_SuicideEnd.json"
2023-01-26T16:06:32.471867Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:32.471869Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:32.472043Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcode_11_SuicideEnd"
2023-01-26T16:06:32.472048Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:32.472054Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:32.472056Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcode_11_SuicideEnd"::Merge::0
2023-01-26T16:06:32.472058Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcode_11_SuicideEnd.json"
2023-01-26T16:06:32.472061Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:32.472064Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:32.472263Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcode_11_SuicideEnd"
2023-01-26T16:06:32.472269Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:32.473959Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:350.824176ms
2023-01-26T16:06:32.757587Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_110.json", Total Files :: 1
2023-01-26T16:06:32.787420Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:32.787554Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:32.787558Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:32.787609Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:32.787612Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:32.787668Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:32.787671Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:32.787725Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:32.787728Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:32.787778Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:32.787850Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:32.787853Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110"::Istanbul::0
2023-01-26T16:06:32.787857Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_110.json"
2023-01-26T16:06:32.787861Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:32.787862Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:33.166364Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110"
2023-01-26T16:06:33.166381Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:06:33.166394Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:33.166400Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110"::Berlin::0
2023-01-26T16:06:33.166402Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_110.json"
2023-01-26T16:06:33.166406Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:33.166407Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:33.166621Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110"
2023-01-26T16:06:33.166628Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:06:33.166636Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:33.166640Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110"::London::0
2023-01-26T16:06:33.166642Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_110.json"
2023-01-26T16:06:33.166646Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:33.166648Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:33.166878Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110"
2023-01-26T16:06:33.166885Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:06:33.166893Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:33.166896Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110"::Merge::0
2023-01-26T16:06:33.166898Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_110.json"
2023-01-26T16:06:33.166902Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:33.166903Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:33.167130Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110"
2023-01-26T16:06:33.167136Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:06:33.169149Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:379.728665ms
2023-01-26T16:06:33.465121Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_110_OOGE.json", Total Files :: 1
2023-01-26T16:06:33.494007Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:33.494142Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:33.494146Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:33.494199Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:33.494201Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:33.494259Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:33.494261Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:33.494318Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:33.494320Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:33.494371Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:33.494471Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:33.494477Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_OOGE"::Istanbul::0
2023-01-26T16:06:33.494481Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_110_OOGE.json"
2023-01-26T16:06:33.494485Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:33.494487Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:33.891143Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_OOGE"
2023-01-26T16:06:33.891158Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:33.891171Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:33.891175Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_OOGE"::Berlin::0
2023-01-26T16:06:33.891177Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_110_OOGE.json"
2023-01-26T16:06:33.891181Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:33.891182Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:33.891419Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_OOGE"
2023-01-26T16:06:33.891424Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:33.891431Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:33.891433Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_OOGE"::London::0
2023-01-26T16:06:33.891435Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_110_OOGE.json"
2023-01-26T16:06:33.891438Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:33.891439Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:33.891666Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_OOGE"
2023-01-26T16:06:33.891671Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:33.891677Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:33.891680Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_OOGE"::Merge::0
2023-01-26T16:06:33.891682Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_110_OOGE.json"
2023-01-26T16:06:33.891685Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:33.891687Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:33.891918Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_OOGE"
2023-01-26T16:06:33.891923Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:33.893556Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:397.928122ms
2023-01-26T16:06:34.178589Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_110_OOGMAfter.json", Total Files :: 1
2023-01-26T16:06:34.207776Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:34.207920Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:34.207925Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:34.207977Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:34.207980Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:34.208041Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:34.208043Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:34.208101Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:34.208104Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:34.208157Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:34.208234Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:34.208237Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_OOGMAfter"::Istanbul::0
2023-01-26T16:06:34.208239Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_110_OOGMAfter.json"
2023-01-26T16:06:34.208243Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:34.208245Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:34.599332Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_OOGMAfter"
2023-01-26T16:06:34.599348Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4331310,
    events_root: None,
}
2023-01-26T16:06:34.599362Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:34.599366Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_OOGMAfter"::Berlin::0
2023-01-26T16:06:34.599368Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_110_OOGMAfter.json"
2023-01-26T16:06:34.599371Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:34.599372Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:34.599679Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_OOGMAfter"
2023-01-26T16:06:34.599684Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3433996,
    events_root: None,
}
2023-01-26T16:06:34.599691Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:34.599693Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_OOGMAfter"::London::0
2023-01-26T16:06:34.599695Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_110_OOGMAfter.json"
2023-01-26T16:06:34.599698Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:34.599699Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:34.599927Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_OOGMAfter"
2023-01-26T16:06:34.599932Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3433996,
    events_root: None,
}
2023-01-26T16:06:34.599939Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:34.599941Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_OOGMAfter"::Merge::0
2023-01-26T16:06:34.599943Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_110_OOGMAfter.json"
2023-01-26T16:06:34.599946Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:34.599947Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:34.600175Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_OOGMAfter"
2023-01-26T16:06:34.600180Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3433996,
    events_root: None,
}
2023-01-26T16:06:34.601843Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:392.416457ms
2023-01-26T16:06:34.868768Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_110_OOGMBefore.json", Total Files :: 1
2023-01-26T16:06:34.898741Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:34.898880Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:34.898883Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:34.898937Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:34.898939Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:34.899000Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:34.899002Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:34.899059Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:34.899061Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:34.899115Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:34.899190Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:34.899193Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_OOGMBefore"::Istanbul::0
2023-01-26T16:06:34.899196Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_110_OOGMBefore.json"
2023-01-26T16:06:34.899200Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:34.899201Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:35.269085Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_OOGMBefore"
2023-01-26T16:06:35.269100Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:35.269114Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:35.269119Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_OOGMBefore"::Berlin::0
2023-01-26T16:06:35.269122Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_110_OOGMBefore.json"
2023-01-26T16:06:35.269126Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:35.269128Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:35.269381Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_OOGMBefore"
2023-01-26T16:06:35.269387Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:35.269395Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:35.269399Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_OOGMBefore"::London::0
2023-01-26T16:06:35.269401Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_110_OOGMBefore.json"
2023-01-26T16:06:35.269405Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:35.269407Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:35.269655Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_OOGMBefore"
2023-01-26T16:06:35.269661Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:35.269669Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:35.269672Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_OOGMBefore"::Merge::0
2023-01-26T16:06:35.269675Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_110_OOGMBefore.json"
2023-01-26T16:06:35.269681Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:35.269683Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:35.269922Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_OOGMBefore"
2023-01-26T16:06:35.269927Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:35.271564Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:371.200603ms
2023-01-26T16:06:35.559042Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_110_SuicideEnd.json", Total Files :: 1
2023-01-26T16:06:35.588256Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:35.588389Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:35.588393Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:35.588445Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:35.588447Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:35.588506Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:35.588508Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:35.588563Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:35.588565Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:35.588617Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:35.588687Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:35.588691Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_SuicideEnd"::Istanbul::0
2023-01-26T16:06:35.588694Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_110_SuicideEnd.json"
2023-01-26T16:06:35.588698Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:35.588699Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:35.963984Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_SuicideEnd"
2023-01-26T16:06:35.963995Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:35.964006Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:35.964010Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_SuicideEnd"::Berlin::0
2023-01-26T16:06:35.964012Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_110_SuicideEnd.json"
2023-01-26T16:06:35.964016Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:35.964017Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:35.964193Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_SuicideEnd"
2023-01-26T16:06:35.964198Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:35.964204Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:35.964206Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_SuicideEnd"::London::0
2023-01-26T16:06:35.964208Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_110_SuicideEnd.json"
2023-01-26T16:06:35.964211Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:35.964212Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:35.964375Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_SuicideEnd"
2023-01-26T16:06:35.964380Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:35.964386Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:35.964388Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_SuicideEnd"::Merge::0
2023-01-26T16:06:35.964390Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_110_SuicideEnd.json"
2023-01-26T16:06:35.964393Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:35.964394Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:35.964556Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_SuicideEnd"
2023-01-26T16:06:35.964561Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:35.966074Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:376.317477ms
2023-01-26T16:06:36.265887Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_110_SuicideMiddle.json", Total Files :: 1
2023-01-26T16:06:36.295381Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:36.295523Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:36.295527Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:36.295578Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:36.295580Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:36.295640Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:36.295642Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:36.295698Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:36.295700Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:36.295752Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:36.295826Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:36.295829Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_SuicideMiddle"::Istanbul::0
2023-01-26T16:06:36.295832Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_110_SuicideMiddle.json"
2023-01-26T16:06:36.295836Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:36.295837Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:36.667173Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_SuicideMiddle"
2023-01-26T16:06:36.667191Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:36.667207Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:36.667212Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_SuicideMiddle"::Berlin::0
2023-01-26T16:06:36.667215Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_110_SuicideMiddle.json"
2023-01-26T16:06:36.667219Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:36.667222Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:36.667448Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_SuicideMiddle"
2023-01-26T16:06:36.667454Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:36.667463Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:36.667465Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_SuicideMiddle"::London::0
2023-01-26T16:06:36.667467Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_110_SuicideMiddle.json"
2023-01-26T16:06:36.667470Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:36.667472Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:36.667695Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_SuicideMiddle"
2023-01-26T16:06:36.667700Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:36.667709Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:36.667712Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_110_SuicideMiddle"::Merge::0
2023-01-26T16:06:36.667713Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_110_SuicideMiddle.json"
2023-01-26T16:06:36.667716Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:36.667718Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:36.667897Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_110_SuicideMiddle"
2023-01-26T16:06:36.667901Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:36.669704Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:372.533396ms
2023-01-26T16:06:36.949887Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_ABCB_RECURSIVE.json", Total Files :: 1
2023-01-26T16:06:36.978798Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:36.978940Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:36.978944Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:36.978997Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:36.978999Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:36.979059Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:36.979060Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:36.979116Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:36.979186Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:36.979189Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_ABCB_RECURSIVE"::Istanbul::0
2023-01-26T16:06:36.979192Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_ABCB_RECURSIVE.json"
2023-01-26T16:06:36.979196Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:36.979198Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:37.346503Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_ABCB_RECURSIVE"
2023-01-26T16:06:37.346517Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6985160,
    events_root: None,
}
2023-01-26T16:06:37.346536Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:37.346541Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_ABCB_RECURSIVE"::Berlin::0
2023-01-26T16:06:37.346543Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_ABCB_RECURSIVE.json"
2023-01-26T16:06:37.346549Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:37.346550Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:37.346940Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_ABCB_RECURSIVE"
2023-01-26T16:06:37.346945Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6101382,
    events_root: None,
}
2023-01-26T16:06:37.346955Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:37.346957Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_ABCB_RECURSIVE"::London::0
2023-01-26T16:06:37.346959Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_ABCB_RECURSIVE.json"
2023-01-26T16:06:37.346962Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:37.346963Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:37.347353Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_ABCB_RECURSIVE"
2023-01-26T16:06:37.347358Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6101382,
    events_root: None,
}
2023-01-26T16:06:37.347367Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:37.347369Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecall_ABCB_RECURSIVE"::Merge::0
2023-01-26T16:06:37.347372Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecall_ABCB_RECURSIVE.json"
2023-01-26T16:06:37.347375Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:37.347376Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:37.347758Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecall_ABCB_RECURSIVE"
2023-01-26T16:06:37.347762Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6101382,
    events_root: None,
}
2023-01-26T16:06:37.349761Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:368.97908ms
2023-01-26T16:06:37.621613Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecallcode_111.json", Total Files :: 1
2023-01-26T16:06:37.652982Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:37.653117Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:37.653121Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:37.653173Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:37.653175Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:37.653231Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:37.653233Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:37.653288Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:37.653290Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:37.653340Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:37.653411Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:37.653413Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111"::Istanbul::0
2023-01-26T16:06:37.653416Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecallcode_111.json"
2023-01-26T16:06:37.653420Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:37.653422Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:38.021770Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111"
2023-01-26T16:06:38.021786Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:06:38.021802Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:38.021807Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111"::Berlin::0
2023-01-26T16:06:38.021810Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecallcode_111.json"
2023-01-26T16:06:38.021814Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:38.021816Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:38.022001Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111"
2023-01-26T16:06:38.022006Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:06:38.022017Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:38.022020Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111"::London::0
2023-01-26T16:06:38.022023Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecallcode_111.json"
2023-01-26T16:06:38.022026Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:38.022028Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:38.022200Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111"
2023-01-26T16:06:38.022205Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:06:38.022215Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:38.022218Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111"::Merge::0
2023-01-26T16:06:38.022221Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecallcode_111.json"
2023-01-26T16:06:38.022225Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:38.022227Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:38.022434Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111"
2023-01-26T16:06:38.022439Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2946713,
    events_root: None,
}
2023-01-26T16:06:38.024365Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:369.472461ms
2023-01-26T16:06:38.314596Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecallcode_111_OOGE.json", Total Files :: 1
2023-01-26T16:06:38.344118Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:38.344254Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:38.344257Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:38.344310Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:38.344312Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:38.344370Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:38.344372Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:38.344430Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:38.344432Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:38.344484Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:38.344556Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:38.344559Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_OOGE"::Istanbul::0
2023-01-26T16:06:38.344562Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecallcode_111_OOGE.json"
2023-01-26T16:06:38.344566Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:38.344567Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:38.728625Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_OOGE"
2023-01-26T16:06:38.728651Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:38.728666Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:38.728673Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_OOGE"::Berlin::0
2023-01-26T16:06:38.728677Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecallcode_111_OOGE.json"
2023-01-26T16:06:38.728683Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:38.728685Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:38.728976Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_OOGE"
2023-01-26T16:06:38.728983Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:38.728992Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:38.728995Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_OOGE"::London::0
2023-01-26T16:06:38.728998Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecallcode_111_OOGE.json"
2023-01-26T16:06:38.729002Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:38.729004Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:38.729300Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_OOGE"
2023-01-26T16:06:38.729306Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:38.729316Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:38.729318Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_OOGE"::Merge::0
2023-01-26T16:06:38.729321Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecallcode_111_OOGE.json"
2023-01-26T16:06:38.729325Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:38.729327Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:38.729672Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_OOGE"
2023-01-26T16:06:38.729689Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:38.732026Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:385.592949ms
2023-01-26T16:06:39.015834Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecallcode_111_OOGMAfter.json", Total Files :: 1
2023-01-26T16:06:39.045888Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:39.046030Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:39.046033Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:39.046085Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:39.046088Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:39.046148Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:39.046150Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:39.046206Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:39.046209Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:39.046261Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:39.046336Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:39.046339Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_OOGMAfter"::Istanbul::0
2023-01-26T16:06:39.046342Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecallcode_111_OOGMAfter.json"
2023-01-26T16:06:39.046346Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:39.046347Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:39.429993Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_OOGMAfter"
2023-01-26T16:06:39.430011Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4331310,
    events_root: None,
}
2023-01-26T16:06:39.430027Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:39.430033Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_OOGMAfter"::Berlin::0
2023-01-26T16:06:39.430035Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecallcode_111_OOGMAfter.json"
2023-01-26T16:06:39.430041Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:39.430043Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:39.430303Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_OOGMAfter"
2023-01-26T16:06:39.430309Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3433996,
    events_root: None,
}
2023-01-26T16:06:39.430318Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:39.430321Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_OOGMAfter"::London::0
2023-01-26T16:06:39.430324Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecallcode_111_OOGMAfter.json"
2023-01-26T16:06:39.430328Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:39.430330Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:39.430572Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_OOGMAfter"
2023-01-26T16:06:39.430578Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3433996,
    events_root: None,
}
2023-01-26T16:06:39.430588Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:39.430591Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_OOGMAfter"::Merge::0
2023-01-26T16:06:39.430594Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecallcode_111_OOGMAfter.json"
2023-01-26T16:06:39.430598Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:39.430600Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:39.430845Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_OOGMAfter"
2023-01-26T16:06:39.430850Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3433996,
    events_root: None,
}
2023-01-26T16:06:39.433386Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:384.975334ms
2023-01-26T16:06:39.724401Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecallcode_111_OOGMBefore.json", Total Files :: 1
2023-01-26T16:06:39.755200Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:39.755345Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:39.755348Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:39.755401Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:39.755403Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:39.755463Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:39.755465Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:39.755530Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:39.755534Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:39.755590Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:39.755663Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:39.755666Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_OOGMBefore"::Istanbul::0
2023-01-26T16:06:39.755669Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecallcode_111_OOGMBefore.json"
2023-01-26T16:06:39.755673Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:39.755675Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:40.167572Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_OOGMBefore"
2023-01-26T16:06:40.167588Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:40.167602Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:40.167607Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_OOGMBefore"::Berlin::0
2023-01-26T16:06:40.167609Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecallcode_111_OOGMBefore.json"
2023-01-26T16:06:40.167613Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:40.167615Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:40.167859Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_OOGMBefore"
2023-01-26T16:06:40.167864Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:40.167873Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:40.167876Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_OOGMBefore"::London::0
2023-01-26T16:06:40.167879Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecallcode_111_OOGMBefore.json"
2023-01-26T16:06:40.167884Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:40.167886Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:40.168120Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_OOGMBefore"
2023-01-26T16:06:40.168125Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:40.168135Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:40.168138Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_OOGMBefore"::Merge::0
2023-01-26T16:06:40.168141Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecallcode_111_OOGMBefore.json"
2023-01-26T16:06:40.168145Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:40.168147Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:40.168405Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_OOGMBefore"
2023-01-26T16:06:40.168410Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3396713,
    events_root: None,
}
2023-01-26T16:06:40.170055Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:413.22288ms
2023-01-26T16:06:40.448624Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecallcode_111_SuicideEnd.json", Total Files :: 1
2023-01-26T16:06:40.480134Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:40.480278Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:40.480282Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:40.480337Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:40.480339Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:40.480401Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:40.480403Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:40.480461Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:40.480464Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:40.480518Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:40.480593Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:40.480596Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_SuicideEnd"::Istanbul::0
2023-01-26T16:06:40.480599Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecallcode_111_SuicideEnd.json"
2023-01-26T16:06:40.480603Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:40.480604Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:40.862272Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_SuicideEnd"
2023-01-26T16:06:40.862288Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:40.862302Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:40.862306Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_SuicideEnd"::Berlin::0
2023-01-26T16:06:40.862308Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecallcode_111_SuicideEnd.json"
2023-01-26T16:06:40.862311Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:40.862313Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:40.862505Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_SuicideEnd"
2023-01-26T16:06:40.862510Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:40.862516Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:40.862519Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_SuicideEnd"::London::0
2023-01-26T16:06:40.862521Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecallcode_111_SuicideEnd.json"
2023-01-26T16:06:40.862524Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:40.862525Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:40.862709Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_SuicideEnd"
2023-01-26T16:06:40.862714Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:40.862721Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:40.862723Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_SuicideEnd"::Merge::0
2023-01-26T16:06:40.862726Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecallcode_111_SuicideEnd.json"
2023-01-26T16:06:40.862729Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:40.862730Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:40.862906Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_SuicideEnd"
2023-01-26T16:06:40.862911Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:40.864526Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:382.788149ms
2023-01-26T16:06:41.138367Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecallcode_111_SuicideMiddle.json", Total Files :: 1
2023-01-26T16:06:41.168830Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:41.168968Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:41.168972Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:41.169026Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:41.169028Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:41.169088Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:41.169090Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:41.169146Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:41.169149Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-26T16:06:41.169209Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:41.169283Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:41.169286Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_SuicideMiddle"::Istanbul::0
2023-01-26T16:06:41.169289Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecallcode_111_SuicideMiddle.json"
2023-01-26T16:06:41.169293Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:41.169295Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:41.517205Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_SuicideMiddle"
2023-01-26T16:06:41.517221Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:41.517234Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:41.517238Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_SuicideMiddle"::Berlin::0
2023-01-26T16:06:41.517240Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecallcode_111_SuicideMiddle.json"
2023-01-26T16:06:41.517244Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:41.517245Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:41.517477Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_SuicideMiddle"
2023-01-26T16:06:41.517483Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:41.517489Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:41.517492Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_SuicideMiddle"::London::0
2023-01-26T16:06:41.517494Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecallcode_111_SuicideMiddle.json"
2023-01-26T16:06:41.517497Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:41.517498Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:41.517675Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_SuicideMiddle"
2023-01-26T16:06:41.517681Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:41.517687Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:41.517689Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_111_SuicideMiddle"::Merge::0
2023-01-26T16:06:41.517691Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecallcode_111_SuicideMiddle.json"
2023-01-26T16:06:41.517693Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:41.517696Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:41.517870Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_111_SuicideMiddle"
2023-01-26T16:06:41.517874Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746713,
    events_root: None,
}
2023-01-26T16:06:41.519687Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:349.05599ms
2023-01-26T16:06:41.800514Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecallcode_ABCB_RECURSIVE.json", Total Files :: 1
2023-01-26T16:06:41.830200Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T16:06:41.830340Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:41.830344Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T16:06:41.830399Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:41.830402Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T16:06:41.830467Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:41.830470Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-26T16:06:41.830526Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T16:06:41.830600Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T16:06:41.830603Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_ABCB_RECURSIVE"::Istanbul::0
2023-01-26T16:06:41.830606Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecallcode_ABCB_RECURSIVE.json"
2023-01-26T16:06:41.830610Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:41.830611Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:42.209237Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_ABCB_RECURSIVE"
2023-01-26T16:06:42.209256Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6985160,
    events_root: None,
}
2023-01-26T16:06:42.209276Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T16:06:42.209280Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_ABCB_RECURSIVE"::Berlin::0
2023-01-26T16:06:42.209282Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecallcode_ABCB_RECURSIVE.json"
2023-01-26T16:06:42.209285Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:42.209287Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:42.209702Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_ABCB_RECURSIVE"
2023-01-26T16:06:42.209707Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6101382,
    events_root: None,
}
2023-01-26T16:06:42.209721Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T16:06:42.209723Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_ABCB_RECURSIVE"::London::0
2023-01-26T16:06:42.209725Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecallcode_ABCB_RECURSIVE.json"
2023-01-26T16:06:42.209728Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:42.209730Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:42.210119Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_ABCB_RECURSIVE"
2023-01-26T16:06:42.210124Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6101382,
    events_root: None,
}
2023-01-26T16:06:42.210138Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T16:06:42.210140Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodecallcodecallcode_ABCB_RECURSIVE"::Merge::0
2023-01-26T16:06:42.210143Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stCallDelegateCodesHomestead/callcodecallcodecallcode_ABCB_RECURSIVE.json"
2023-01-26T16:06:42.210145Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T16:06:42.210147Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T16:06:42.210534Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodecallcodecallcode_ABCB_RECURSIVE"
2023-01-26T16:06:42.210539Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6101382,
    events_root: None,
}
2023-01-26T16:06:42.212296Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:380.356284ms
```
