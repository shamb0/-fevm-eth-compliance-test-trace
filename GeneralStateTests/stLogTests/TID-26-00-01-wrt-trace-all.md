> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stLogTests

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stLogTests \
	cargo run --release \
	-- \
	statetest
```

> For Review

* Execution looks OK, all use-cases passed.

> Execution Trace

```
2023-01-26T07:35:27.289912Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log0_emptyMem.json", Total Files :: 1
2023-01-26T07:35:27.360631Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:27.360838Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:27.360842Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:27.360895Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:27.360898Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:27.360958Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:27.361031Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:27.361034Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log0_emptyMem"::Istanbul::0
2023-01-26T07:35:27.361037Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log0_emptyMem.json"
2023-01-26T07:35:27.361040Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:27.361041Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:27.698796Z  INFO evm_eth_compliance::statetest::runner: UC : "log0_emptyMem"
2023-01-26T07:35:27.698812Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:27.698822Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:27.698828Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log0_emptyMem"::Berlin::0
2023-01-26T07:35:27.698830Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log0_emptyMem.json"
2023-01-26T07:35:27.698833Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:27.698834Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:27.698957Z  INFO evm_eth_compliance::statetest::runner: UC : "log0_emptyMem"
2023-01-26T07:35:27.698961Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:27.698967Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:27.698970Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log0_emptyMem"::London::0
2023-01-26T07:35:27.698972Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log0_emptyMem.json"
2023-01-26T07:35:27.698974Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:27.698976Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:27.699085Z  INFO evm_eth_compliance::statetest::runner: UC : "log0_emptyMem"
2023-01-26T07:35:27.699089Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:27.699095Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:27.699098Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log0_emptyMem"::Merge::0
2023-01-26T07:35:27.699100Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log0_emptyMem.json"
2023-01-26T07:35:27.699102Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:27.699103Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:27.699208Z  INFO evm_eth_compliance::statetest::runner: UC : "log0_emptyMem"
2023-01-26T07:35:27.699212Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:27.700704Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:338.591768ms
2023-01-26T07:35:27.966006Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log0_logMemStartTooHigh.json", Total Files :: 1
2023-01-26T07:35:28.285031Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:28.285234Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:28.285238Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:28.285291Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:28.285294Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:28.285355Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:28.285428Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:28.285431Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log0_logMemStartTooHigh"::Istanbul::0
2023-01-26T07:35:28.285434Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log0_logMemStartTooHigh.json"
2023-01-26T07:35:28.285437Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:28.285439Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:28.652137Z  INFO evm_eth_compliance::statetest::runner: UC : "log0_logMemStartTooHigh"
2023-01-26T07:35:28.652153Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:28.652164Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:28.652171Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log0_logMemStartTooHigh"::Berlin::0
2023-01-26T07:35:28.652173Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log0_logMemStartTooHigh.json"
2023-01-26T07:35:28.652176Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:28.652178Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:28.652336Z  INFO evm_eth_compliance::statetest::runner: UC : "log0_logMemStartTooHigh"
2023-01-26T07:35:28.652342Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:28.652349Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:28.652353Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log0_logMemStartTooHigh"::London::0
2023-01-26T07:35:28.652356Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log0_logMemStartTooHigh.json"
2023-01-26T07:35:28.652359Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:28.652361Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:28.652523Z  INFO evm_eth_compliance::statetest::runner: UC : "log0_logMemStartTooHigh"
2023-01-26T07:35:28.652527Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:28.652533Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:28.652535Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log0_logMemStartTooHigh"::Merge::0
2023-01-26T07:35:28.652537Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log0_logMemStartTooHigh.json"
2023-01-26T07:35:28.652540Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:28.652541Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:28.652651Z  INFO evm_eth_compliance::statetest::runner: UC : "log0_logMemStartTooHigh"
2023-01-26T07:35:28.652655Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:28.654190Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:367.633108ms
2023-01-26T07:35:28.920186Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log0_logMemsizeTooHigh.json", Total Files :: 1
2023-01-26T07:35:28.950116Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:28.950329Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:28.950333Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:28.950387Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:28.950390Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:28.950451Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:28.950540Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:28.950543Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log0_logMemsizeTooHigh"::Istanbul::0
2023-01-26T07:35:28.950546Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log0_logMemsizeTooHigh.json"
2023-01-26T07:35:28.950549Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:28.950551Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:29.296531Z  INFO evm_eth_compliance::statetest::runner: UC : "log0_logMemsizeTooHigh"
2023-01-26T07:35:29.296548Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:29.296561Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:29.296569Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log0_logMemsizeTooHigh"::Berlin::0
2023-01-26T07:35:29.296571Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log0_logMemsizeTooHigh.json"
2023-01-26T07:35:29.296575Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:29.296577Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:29.296700Z  INFO evm_eth_compliance::statetest::runner: UC : "log0_logMemsizeTooHigh"
2023-01-26T07:35:29.296705Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:29.296712Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:29.296715Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log0_logMemsizeTooHigh"::London::0
2023-01-26T07:35:29.296718Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log0_logMemsizeTooHigh.json"
2023-01-26T07:35:29.296721Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:29.296724Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:29.296852Z  INFO evm_eth_compliance::statetest::runner: UC : "log0_logMemsizeTooHigh"
2023-01-26T07:35:29.296857Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:29.296864Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:29.296867Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log0_logMemsizeTooHigh"::Merge::0
2023-01-26T07:35:29.296870Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log0_logMemsizeTooHigh.json"
2023-01-26T07:35:29.296873Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:29.296876Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:29.296990Z  INFO evm_eth_compliance::statetest::runner: UC : "log0_logMemsizeTooHigh"
2023-01-26T07:35:29.296994Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:29.298662Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:346.889508ms
2023-01-26T07:35:29.572880Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log0_logMemsizeZero.json", Total Files :: 1
2023-01-26T07:35:29.603070Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:29.603274Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:29.603278Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:29.603332Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:29.603334Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:29.603396Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:29.603470Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:29.603473Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log0_logMemsizeZero"::Istanbul::0
2023-01-26T07:35:29.603476Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log0_logMemsizeZero.json"
2023-01-26T07:35:29.603479Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:29.603481Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:29.956860Z  INFO evm_eth_compliance::statetest::runner: UC : "log0_logMemsizeZero"
2023-01-26T07:35:29.956875Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:29.956886Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:29.956893Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log0_logMemsizeZero"::Berlin::0
2023-01-26T07:35:29.956895Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log0_logMemsizeZero.json"
2023-01-26T07:35:29.956898Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:29.956899Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:29.957024Z  INFO evm_eth_compliance::statetest::runner: UC : "log0_logMemsizeZero"
2023-01-26T07:35:29.957028Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:29.957034Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:29.957036Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log0_logMemsizeZero"::London::0
2023-01-26T07:35:29.957038Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log0_logMemsizeZero.json"
2023-01-26T07:35:29.957041Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:29.957042Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:29.957175Z  INFO evm_eth_compliance::statetest::runner: UC : "log0_logMemsizeZero"
2023-01-26T07:35:29.957179Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:29.957184Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:29.957187Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log0_logMemsizeZero"::Merge::0
2023-01-26T07:35:29.957189Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log0_logMemsizeZero.json"
2023-01-26T07:35:29.957192Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:29.957193Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:29.957303Z  INFO evm_eth_compliance::statetest::runner: UC : "log0_logMemsizeZero"
2023-01-26T07:35:29.957307Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:29.958889Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:354.247814ms
2023-01-26T07:35:30.241089Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log0_nonEmptyMem.json", Total Files :: 1
2023-01-26T07:35:30.282186Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:30.282384Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:30.282387Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:30.282438Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:30.282440Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:30.282502Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:30.282573Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:30.282576Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log0_nonEmptyMem"::Istanbul::0
2023-01-26T07:35:30.282579Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log0_nonEmptyMem.json"
2023-01-26T07:35:30.282582Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:30.282583Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:30.649224Z  INFO evm_eth_compliance::statetest::runner: UC : "log0_nonEmptyMem"
2023-01-26T07:35:30.649239Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:30.649252Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:30.649258Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log0_nonEmptyMem"::Berlin::0
2023-01-26T07:35:30.649260Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log0_nonEmptyMem.json"
2023-01-26T07:35:30.649263Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:30.649264Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:30.649405Z  INFO evm_eth_compliance::statetest::runner: UC : "log0_nonEmptyMem"
2023-01-26T07:35:30.649409Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:30.649415Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:30.649417Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log0_nonEmptyMem"::London::0
2023-01-26T07:35:30.649419Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log0_nonEmptyMem.json"
2023-01-26T07:35:30.649422Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:30.649423Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:30.649533Z  INFO evm_eth_compliance::statetest::runner: UC : "log0_nonEmptyMem"
2023-01-26T07:35:30.649537Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:30.649542Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:30.649545Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log0_nonEmptyMem"::Merge::0
2023-01-26T07:35:30.649547Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log0_nonEmptyMem.json"
2023-01-26T07:35:30.649549Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:30.649551Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:30.649657Z  INFO evm_eth_compliance::statetest::runner: UC : "log0_nonEmptyMem"
2023-01-26T07:35:30.649661Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:30.651210Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:367.485696ms
2023-01-26T07:35:30.933973Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log0_nonEmptyMem_logMemSize1.json", Total Files :: 1
2023-01-26T07:35:30.963560Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:30.963763Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:30.963766Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:30.963818Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:30.963821Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:30.963883Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:30.963957Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:30.963961Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log0_nonEmptyMem_logMemSize1"::Istanbul::0
2023-01-26T07:35:30.963964Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log0_nonEmptyMem_logMemSize1.json"
2023-01-26T07:35:30.963967Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:30.963968Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:31.334257Z  INFO evm_eth_compliance::statetest::runner: UC : "log0_nonEmptyMem_logMemSize1"
2023-01-26T07:35:31.334273Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:31.334286Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:31.334293Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log0_nonEmptyMem_logMemSize1"::Berlin::0
2023-01-26T07:35:31.334295Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log0_nonEmptyMem_logMemSize1.json"
2023-01-26T07:35:31.334298Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:31.334299Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:31.334421Z  INFO evm_eth_compliance::statetest::runner: UC : "log0_nonEmptyMem_logMemSize1"
2023-01-26T07:35:31.334425Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:31.334431Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:31.334433Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log0_nonEmptyMem_logMemSize1"::London::0
2023-01-26T07:35:31.334435Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log0_nonEmptyMem_logMemSize1.json"
2023-01-26T07:35:31.334438Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:31.334439Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:31.334569Z  INFO evm_eth_compliance::statetest::runner: UC : "log0_nonEmptyMem_logMemSize1"
2023-01-26T07:35:31.334573Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:31.334578Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:31.334581Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log0_nonEmptyMem_logMemSize1"::Merge::0
2023-01-26T07:35:31.334583Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log0_nonEmptyMem_logMemSize1.json"
2023-01-26T07:35:31.334585Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:31.334586Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:31.334710Z  INFO evm_eth_compliance::statetest::runner: UC : "log0_nonEmptyMem_logMemSize1"
2023-01-26T07:35:31.334715Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:31.336420Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:371.16658ms
2023-01-26T07:35:31.597839Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log0_nonEmptyMem_logMemSize1_logMemStart31.json", Total Files :: 1
2023-01-26T07:35:31.644588Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:31.644853Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:31.644861Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:31.644932Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:31.644935Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:31.645020Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:31.645122Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:31.645127Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log0_nonEmptyMem_logMemSize1_logMemStart31"::Istanbul::0
2023-01-26T07:35:31.645131Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log0_nonEmptyMem_logMemSize1_logMemStart31.json"
2023-01-26T07:35:31.645135Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:31.645137Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:31.982677Z  INFO evm_eth_compliance::statetest::runner: UC : "log0_nonEmptyMem_logMemSize1_logMemStart31"
2023-01-26T07:35:31.982692Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:31.982704Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:31.982710Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log0_nonEmptyMem_logMemSize1_logMemStart31"::Berlin::0
2023-01-26T07:35:31.982713Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log0_nonEmptyMem_logMemSize1_logMemStart31.json"
2023-01-26T07:35:31.982716Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:31.982717Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:31.982840Z  INFO evm_eth_compliance::statetest::runner: UC : "log0_nonEmptyMem_logMemSize1_logMemStart31"
2023-01-26T07:35:31.982845Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:31.982851Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:31.982854Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log0_nonEmptyMem_logMemSize1_logMemStart31"::London::0
2023-01-26T07:35:31.982856Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log0_nonEmptyMem_logMemSize1_logMemStart31.json"
2023-01-26T07:35:31.982860Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:31.982861Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:31.982975Z  INFO evm_eth_compliance::statetest::runner: UC : "log0_nonEmptyMem_logMemSize1_logMemStart31"
2023-01-26T07:35:31.982981Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:31.982986Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:31.982988Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log0_nonEmptyMem_logMemSize1_logMemStart31"::Merge::0
2023-01-26T07:35:31.982991Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log0_nonEmptyMem_logMemSize1_logMemStart31.json"
2023-01-26T07:35:31.982994Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:31.982995Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:31.983103Z  INFO evm_eth_compliance::statetest::runner: UC : "log0_nonEmptyMem_logMemSize1_logMemStart31"
2023-01-26T07:35:31.983108Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:31.984726Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:338.530502ms
2023-01-26T07:35:32.263834Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log1_Caller.json", Total Files :: 1
2023-01-26T07:35:32.311034Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:32.311228Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:32.311232Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:32.311283Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:32.311285Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:32.311345Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:32.311416Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:32.311420Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1_Caller"::Istanbul::0
2023-01-26T07:35:32.311422Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log1_Caller.json"
2023-01-26T07:35:32.311425Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:32.311426Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:32.664010Z  INFO evm_eth_compliance::statetest::runner: UC : "log1_Caller"
2023-01-26T07:35:32.664023Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:32.664034Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:32.664041Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1_Caller"::Berlin::0
2023-01-26T07:35:32.664042Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log1_Caller.json"
2023-01-26T07:35:32.664045Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:32.664047Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:32.664170Z  INFO evm_eth_compliance::statetest::runner: UC : "log1_Caller"
2023-01-26T07:35:32.664175Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:32.664180Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:32.664183Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1_Caller"::London::0
2023-01-26T07:35:32.664184Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log1_Caller.json"
2023-01-26T07:35:32.664187Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:32.664188Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:32.664312Z  INFO evm_eth_compliance::statetest::runner: UC : "log1_Caller"
2023-01-26T07:35:32.664316Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:32.664322Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:32.664324Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1_Caller"::Merge::0
2023-01-26T07:35:32.664326Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log1_Caller.json"
2023-01-26T07:35:32.664328Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:32.664330Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:32.664436Z  INFO evm_eth_compliance::statetest::runner: UC : "log1_Caller"
2023-01-26T07:35:32.664440Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:32.665965Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:353.415777ms
2023-01-26T07:35:32.943798Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log1_MaxTopic.json", Total Files :: 1
2023-01-26T07:35:32.974224Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:32.974499Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:32.974513Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:32.974587Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:32.974597Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:32.974679Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:32.974785Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:32.974792Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1_MaxTopic"::Istanbul::0
2023-01-26T07:35:32.974795Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log1_MaxTopic.json"
2023-01-26T07:35:32.974799Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:32.974801Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:33.315255Z  INFO evm_eth_compliance::statetest::runner: UC : "log1_MaxTopic"
2023-01-26T07:35:33.315272Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:33.315287Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:33.315295Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1_MaxTopic"::Berlin::0
2023-01-26T07:35:33.315296Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log1_MaxTopic.json"
2023-01-26T07:35:33.315299Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:33.315300Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:33.315420Z  INFO evm_eth_compliance::statetest::runner: UC : "log1_MaxTopic"
2023-01-26T07:35:33.315425Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:33.315431Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:33.315434Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1_MaxTopic"::London::0
2023-01-26T07:35:33.315436Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log1_MaxTopic.json"
2023-01-26T07:35:33.315438Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:33.315439Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:33.315566Z  INFO evm_eth_compliance::statetest::runner: UC : "log1_MaxTopic"
2023-01-26T07:35:33.315571Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:33.315576Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:33.315579Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1_MaxTopic"::Merge::0
2023-01-26T07:35:33.315581Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log1_MaxTopic.json"
2023-01-26T07:35:33.315583Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:33.315584Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:33.315689Z  INFO evm_eth_compliance::statetest::runner: UC : "log1_MaxTopic"
2023-01-26T07:35:33.315694Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:33.317454Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:341.479856ms
2023-01-26T07:35:33.590566Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log1_emptyMem.json", Total Files :: 1
2023-01-26T07:35:33.620623Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:33.620818Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:33.620821Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:33.620872Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:33.620874Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:33.620933Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:33.621005Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:33.621008Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1_emptyMem"::Istanbul::0
2023-01-26T07:35:33.621011Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log1_emptyMem.json"
2023-01-26T07:35:33.621013Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:33.621015Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:33.991162Z  INFO evm_eth_compliance::statetest::runner: UC : "log1_emptyMem"
2023-01-26T07:35:33.991179Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:33.991189Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:33.991195Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1_emptyMem"::Berlin::0
2023-01-26T07:35:33.991197Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log1_emptyMem.json"
2023-01-26T07:35:33.991201Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:33.991203Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:33.991325Z  INFO evm_eth_compliance::statetest::runner: UC : "log1_emptyMem"
2023-01-26T07:35:33.991330Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:33.991336Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:33.991338Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1_emptyMem"::London::0
2023-01-26T07:35:33.991340Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log1_emptyMem.json"
2023-01-26T07:35:33.991342Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:33.991344Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:33.991476Z  INFO evm_eth_compliance::statetest::runner: UC : "log1_emptyMem"
2023-01-26T07:35:33.991480Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:33.991486Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:33.991488Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1_emptyMem"::Merge::0
2023-01-26T07:35:33.991490Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log1_emptyMem.json"
2023-01-26T07:35:33.991493Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:33.991494Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:33.991600Z  INFO evm_eth_compliance::statetest::runner: UC : "log1_emptyMem"
2023-01-26T07:35:33.991605Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:33.993239Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:370.991077ms
2023-01-26T07:35:34.277829Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log1_logMemStartTooHigh.json", Total Files :: 1
2023-01-26T07:35:34.331464Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:34.331674Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:34.331678Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:34.331732Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:34.331734Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:34.331803Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:34.331884Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:34.331888Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1_logMemStartTooHigh"::Istanbul::0
2023-01-26T07:35:34.331891Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log1_logMemStartTooHigh.json"
2023-01-26T07:35:34.331894Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:34.331896Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:34.666362Z  INFO evm_eth_compliance::statetest::runner: UC : "log1_logMemStartTooHigh"
2023-01-26T07:35:34.666377Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:34.666390Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:34.666396Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1_logMemStartTooHigh"::Berlin::0
2023-01-26T07:35:34.666398Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log1_logMemStartTooHigh.json"
2023-01-26T07:35:34.666401Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:34.666402Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:34.666517Z  INFO evm_eth_compliance::statetest::runner: UC : "log1_logMemStartTooHigh"
2023-01-26T07:35:34.666522Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:34.666526Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:34.666529Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1_logMemStartTooHigh"::London::0
2023-01-26T07:35:34.666531Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log1_logMemStartTooHigh.json"
2023-01-26T07:35:34.666534Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:34.666535Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:34.666637Z  INFO evm_eth_compliance::statetest::runner: UC : "log1_logMemStartTooHigh"
2023-01-26T07:35:34.666641Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:34.666645Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:34.666648Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1_logMemStartTooHigh"::Merge::0
2023-01-26T07:35:34.666650Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log1_logMemStartTooHigh.json"
2023-01-26T07:35:34.666652Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:34.666654Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:34.666753Z  INFO evm_eth_compliance::statetest::runner: UC : "log1_logMemStartTooHigh"
2023-01-26T07:35:34.666757Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:34.668193Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:335.303857ms
2023-01-26T07:35:34.955081Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log1_logMemsizeTooHigh.json", Total Files :: 1
2023-01-26T07:35:35.022670Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:35.022875Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:35.022879Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:35.022932Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:35.022934Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:35.022996Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:35.023070Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:35.023074Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1_logMemsizeTooHigh"::Istanbul::0
2023-01-26T07:35:35.023076Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log1_logMemsizeTooHigh.json"
2023-01-26T07:35:35.023080Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:35.023081Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:35.360791Z  INFO evm_eth_compliance::statetest::runner: UC : "log1_logMemsizeTooHigh"
2023-01-26T07:35:35.360806Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:35.360818Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:35.360825Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1_logMemsizeTooHigh"::Berlin::0
2023-01-26T07:35:35.360826Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log1_logMemsizeTooHigh.json"
2023-01-26T07:35:35.360829Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:35.360830Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:35.360959Z  INFO evm_eth_compliance::statetest::runner: UC : "log1_logMemsizeTooHigh"
2023-01-26T07:35:35.360964Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:35.360969Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:35.360972Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1_logMemsizeTooHigh"::London::0
2023-01-26T07:35:35.360974Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log1_logMemsizeTooHigh.json"
2023-01-26T07:35:35.360976Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:35.360978Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:35.361096Z  INFO evm_eth_compliance::statetest::runner: UC : "log1_logMemsizeTooHigh"
2023-01-26T07:35:35.361101Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:35.361108Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:35.361110Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1_logMemsizeTooHigh"::Merge::0
2023-01-26T07:35:35.361112Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log1_logMemsizeTooHigh.json"
2023-01-26T07:35:35.361115Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:35.361116Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:35.361226Z  INFO evm_eth_compliance::statetest::runner: UC : "log1_logMemsizeTooHigh"
2023-01-26T07:35:35.361231Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:35.362808Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:338.571957ms
2023-01-26T07:35:35.637526Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log1_logMemsizeZero.json", Total Files :: 1
2023-01-26T07:35:35.698405Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:35.698604Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:35.698607Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:35.698661Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:35.698663Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:35.698726Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:35.698798Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:35.698801Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1_logMemsizeZero"::Istanbul::0
2023-01-26T07:35:35.698804Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log1_logMemsizeZero.json"
2023-01-26T07:35:35.698808Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:35.698809Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:36.075777Z  INFO evm_eth_compliance::statetest::runner: UC : "log1_logMemsizeZero"
2023-01-26T07:35:36.075791Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:36.075803Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:36.075810Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1_logMemsizeZero"::Berlin::0
2023-01-26T07:35:36.075812Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log1_logMemsizeZero.json"
2023-01-26T07:35:36.075816Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:36.075817Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:36.075960Z  INFO evm_eth_compliance::statetest::runner: UC : "log1_logMemsizeZero"
2023-01-26T07:35:36.075965Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:36.075970Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:36.075973Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1_logMemsizeZero"::London::0
2023-01-26T07:35:36.075975Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log1_logMemsizeZero.json"
2023-01-26T07:35:36.075978Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:36.075979Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:36.076090Z  INFO evm_eth_compliance::statetest::runner: UC : "log1_logMemsizeZero"
2023-01-26T07:35:36.076094Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:36.076100Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:36.076102Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1_logMemsizeZero"::Merge::0
2023-01-26T07:35:36.076104Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log1_logMemsizeZero.json"
2023-01-26T07:35:36.076107Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:36.076108Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:36.076213Z  INFO evm_eth_compliance::statetest::runner: UC : "log1_logMemsizeZero"
2023-01-26T07:35:36.076217Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:36.077777Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:377.822641ms
2023-01-26T07:35:36.353924Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log1_nonEmptyMem.json", Total Files :: 1
2023-01-26T07:35:36.408421Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:36.408633Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:36.408639Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:36.408696Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:36.408699Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:36.408763Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:36.408841Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:36.408845Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1_nonEmptyMem"::Istanbul::0
2023-01-26T07:35:36.408849Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log1_nonEmptyMem.json"
2023-01-26T07:35:36.408853Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:36.408855Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:36.763472Z  INFO evm_eth_compliance::statetest::runner: UC : "log1_nonEmptyMem"
2023-01-26T07:35:36.763486Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:36.763499Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:36.763506Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1_nonEmptyMem"::Berlin::0
2023-01-26T07:35:36.763508Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log1_nonEmptyMem.json"
2023-01-26T07:35:36.763511Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:36.763512Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:36.763639Z  INFO evm_eth_compliance::statetest::runner: UC : "log1_nonEmptyMem"
2023-01-26T07:35:36.763644Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:36.763649Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:36.763652Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1_nonEmptyMem"::London::0
2023-01-26T07:35:36.763653Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log1_nonEmptyMem.json"
2023-01-26T07:35:36.763656Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:36.763657Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:36.763761Z  INFO evm_eth_compliance::statetest::runner: UC : "log1_nonEmptyMem"
2023-01-26T07:35:36.763765Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:36.763770Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:36.763773Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1_nonEmptyMem"::Merge::0
2023-01-26T07:35:36.763774Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log1_nonEmptyMem.json"
2023-01-26T07:35:36.763777Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:36.763778Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:36.763879Z  INFO evm_eth_compliance::statetest::runner: UC : "log1_nonEmptyMem"
2023-01-26T07:35:36.763883Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:36.765292Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:355.472378ms
2023-01-26T07:35:37.029789Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log1_nonEmptyMem_logMemSize1.json", Total Files :: 1
2023-01-26T07:35:37.095317Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:37.095523Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:37.095527Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:37.095583Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:37.095585Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:37.095649Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:37.095730Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:37.095734Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1_nonEmptyMem_logMemSize1"::Istanbul::0
2023-01-26T07:35:37.095737Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log1_nonEmptyMem_logMemSize1.json"
2023-01-26T07:35:37.095741Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:37.095743Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:37.443301Z  INFO evm_eth_compliance::statetest::runner: UC : "log1_nonEmptyMem_logMemSize1"
2023-01-26T07:35:37.443318Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:37.443328Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:37.443335Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1_nonEmptyMem_logMemSize1"::Berlin::0
2023-01-26T07:35:37.443337Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log1_nonEmptyMem_logMemSize1.json"
2023-01-26T07:35:37.443340Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:37.443342Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:37.443469Z  INFO evm_eth_compliance::statetest::runner: UC : "log1_nonEmptyMem_logMemSize1"
2023-01-26T07:35:37.443473Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:37.443479Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:37.443482Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1_nonEmptyMem_logMemSize1"::London::0
2023-01-26T07:35:37.443485Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log1_nonEmptyMem_logMemSize1.json"
2023-01-26T07:35:37.443488Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:37.443490Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:37.443632Z  INFO evm_eth_compliance::statetest::runner: UC : "log1_nonEmptyMem_logMemSize1"
2023-01-26T07:35:37.443636Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:37.443643Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:37.443646Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1_nonEmptyMem_logMemSize1"::Merge::0
2023-01-26T07:35:37.443648Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log1_nonEmptyMem_logMemSize1.json"
2023-01-26T07:35:37.443651Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:37.443652Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:37.443765Z  INFO evm_eth_compliance::statetest::runner: UC : "log1_nonEmptyMem_logMemSize1"
2023-01-26T07:35:37.443769Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:37.445409Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:348.463144ms
2023-01-26T07:35:37.730380Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log1_nonEmptyMem_logMemSize1_logMemStart31.json", Total Files :: 1
2023-01-26T07:35:37.759535Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:37.759723Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:37.759728Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:37.759778Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:37.759781Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:37.759839Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:37.759910Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:37.759913Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1_nonEmptyMem_logMemSize1_logMemStart31"::Istanbul::0
2023-01-26T07:35:37.759916Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log1_nonEmptyMem_logMemSize1_logMemStart31.json"
2023-01-26T07:35:37.759919Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:37.759921Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:38.214323Z  INFO evm_eth_compliance::statetest::runner: UC : "log1_nonEmptyMem_logMemSize1_logMemStart31"
2023-01-26T07:35:38.214338Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:38.214349Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:38.214356Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1_nonEmptyMem_logMemSize1_logMemStart31"::Berlin::0
2023-01-26T07:35:38.214358Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log1_nonEmptyMem_logMemSize1_logMemStart31.json"
2023-01-26T07:35:38.214362Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:38.214363Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:38.214487Z  INFO evm_eth_compliance::statetest::runner: UC : "log1_nonEmptyMem_logMemSize1_logMemStart31"
2023-01-26T07:35:38.214491Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:38.214497Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:38.214500Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1_nonEmptyMem_logMemSize1_logMemStart31"::London::0
2023-01-26T07:35:38.214502Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log1_nonEmptyMem_logMemSize1_logMemStart31.json"
2023-01-26T07:35:38.214506Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:38.214507Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:38.214631Z  INFO evm_eth_compliance::statetest::runner: UC : "log1_nonEmptyMem_logMemSize1_logMemStart31"
2023-01-26T07:35:38.214636Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:38.214641Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:38.214644Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1_nonEmptyMem_logMemSize1_logMemStart31"::Merge::0
2023-01-26T07:35:38.214647Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log1_nonEmptyMem_logMemSize1_logMemStart31.json"
2023-01-26T07:35:38.214649Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:38.214651Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:38.214794Z  INFO evm_eth_compliance::statetest::runner: UC : "log1_nonEmptyMem_logMemSize1_logMemStart31"
2023-01-26T07:35:38.214799Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:38.216674Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:455.275587ms
2023-01-26T07:35:38.501339Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log2_Caller.json", Total Files :: 1
2023-01-26T07:35:38.561404Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:38.561599Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:38.561602Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:38.561653Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:38.561654Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:38.561722Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:38.561794Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:38.561797Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2_Caller"::Istanbul::0
2023-01-26T07:35:38.561800Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log2_Caller.json"
2023-01-26T07:35:38.561803Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:38.561805Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:38.938874Z  INFO evm_eth_compliance::statetest::runner: UC : "log2_Caller"
2023-01-26T07:35:38.938891Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:38.938904Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:38.938913Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2_Caller"::Berlin::0
2023-01-26T07:35:38.938915Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log2_Caller.json"
2023-01-26T07:35:38.938918Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:38.938920Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:38.939116Z  INFO evm_eth_compliance::statetest::runner: UC : "log2_Caller"
2023-01-26T07:35:38.939122Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:38.939129Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:38.939132Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2_Caller"::London::0
2023-01-26T07:35:38.939135Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log2_Caller.json"
2023-01-26T07:35:38.939138Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:38.939141Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:38.939284Z  INFO evm_eth_compliance::statetest::runner: UC : "log2_Caller"
2023-01-26T07:35:38.939289Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:38.939296Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:38.939300Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2_Caller"::Merge::0
2023-01-26T07:35:38.939302Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log2_Caller.json"
2023-01-26T07:35:38.939306Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:38.939308Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:38.939443Z  INFO evm_eth_compliance::statetest::runner: UC : "log2_Caller"
2023-01-26T07:35:38.939449Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:38.941213Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:378.0573ms
2023-01-26T07:35:39.223695Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log2_MaxTopic.json", Total Files :: 1
2023-01-26T07:35:39.254723Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:39.254929Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:39.254934Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:39.254991Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:39.254993Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:39.255056Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:39.255133Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:39.255136Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2_MaxTopic"::Istanbul::0
2023-01-26T07:35:39.255139Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log2_MaxTopic.json"
2023-01-26T07:35:39.255142Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:39.255143Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:39.643328Z  INFO evm_eth_compliance::statetest::runner: UC : "log2_MaxTopic"
2023-01-26T07:35:39.643343Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:39.643356Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:39.643363Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2_MaxTopic"::Berlin::0
2023-01-26T07:35:39.643364Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log2_MaxTopic.json"
2023-01-26T07:35:39.643367Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:39.643369Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:39.643489Z  INFO evm_eth_compliance::statetest::runner: UC : "log2_MaxTopic"
2023-01-26T07:35:39.643493Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:39.643499Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:39.643502Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2_MaxTopic"::London::0
2023-01-26T07:35:39.643504Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log2_MaxTopic.json"
2023-01-26T07:35:39.643506Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:39.643507Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:39.643633Z  INFO evm_eth_compliance::statetest::runner: UC : "log2_MaxTopic"
2023-01-26T07:35:39.643638Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:39.643643Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:39.643646Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2_MaxTopic"::Merge::0
2023-01-26T07:35:39.643648Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log2_MaxTopic.json"
2023-01-26T07:35:39.643650Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:39.643651Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:39.643756Z  INFO evm_eth_compliance::statetest::runner: UC : "log2_MaxTopic"
2023-01-26T07:35:39.643760Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:39.645392Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:389.046842ms
2023-01-26T07:35:39.923195Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log2_emptyMem.json", Total Files :: 1
2023-01-26T07:35:39.952851Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:39.953054Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:39.953058Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:39.953114Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:39.953117Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:39.953181Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:39.953256Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:39.953260Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2_emptyMem"::Istanbul::0
2023-01-26T07:35:39.953263Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log2_emptyMem.json"
2023-01-26T07:35:39.953268Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:39.953270Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:40.341666Z  INFO evm_eth_compliance::statetest::runner: UC : "log2_emptyMem"
2023-01-26T07:35:40.341682Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:40.341694Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:40.341701Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2_emptyMem"::Berlin::0
2023-01-26T07:35:40.341702Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log2_emptyMem.json"
2023-01-26T07:35:40.341705Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:40.341707Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:40.341831Z  INFO evm_eth_compliance::statetest::runner: UC : "log2_emptyMem"
2023-01-26T07:35:40.341836Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:40.341841Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:40.341844Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2_emptyMem"::London::0
2023-01-26T07:35:40.341845Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log2_emptyMem.json"
2023-01-26T07:35:40.341848Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:40.341849Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:40.341961Z  INFO evm_eth_compliance::statetest::runner: UC : "log2_emptyMem"
2023-01-26T07:35:40.341965Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:40.341970Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:40.341973Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2_emptyMem"::Merge::0
2023-01-26T07:35:40.341974Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log2_emptyMem.json"
2023-01-26T07:35:40.341977Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:40.341978Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:40.342077Z  INFO evm_eth_compliance::statetest::runner: UC : "log2_emptyMem"
2023-01-26T07:35:40.342081Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:40.343628Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:389.239564ms
2023-01-26T07:35:40.618874Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log2_logMemStartTooHigh.json", Total Files :: 1
2023-01-26T07:35:40.648577Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:40.648774Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:40.648778Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:40.648829Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:40.648831Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:40.648891Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:40.648962Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:40.648965Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2_logMemStartTooHigh"::Istanbul::0
2023-01-26T07:35:40.648968Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log2_logMemStartTooHigh.json"
2023-01-26T07:35:40.648971Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:40.648973Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:41.016110Z  INFO evm_eth_compliance::statetest::runner: UC : "log2_logMemStartTooHigh"
2023-01-26T07:35:41.016127Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:41.016140Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:41.016147Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2_logMemStartTooHigh"::Berlin::0
2023-01-26T07:35:41.016148Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log2_logMemStartTooHigh.json"
2023-01-26T07:35:41.016152Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:41.016153Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:41.016304Z  INFO evm_eth_compliance::statetest::runner: UC : "log2_logMemStartTooHigh"
2023-01-26T07:35:41.016311Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:41.016316Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:41.016319Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2_logMemStartTooHigh"::London::0
2023-01-26T07:35:41.016320Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log2_logMemStartTooHigh.json"
2023-01-26T07:35:41.016323Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:41.016324Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:41.016467Z  INFO evm_eth_compliance::statetest::runner: UC : "log2_logMemStartTooHigh"
2023-01-26T07:35:41.016471Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:41.016477Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:41.016479Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2_logMemStartTooHigh"::Merge::0
2023-01-26T07:35:41.016481Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log2_logMemStartTooHigh.json"
2023-01-26T07:35:41.016483Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:41.016485Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:41.016589Z  INFO evm_eth_compliance::statetest::runner: UC : "log2_logMemStartTooHigh"
2023-01-26T07:35:41.016593Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:41.018413Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:368.026213ms
2023-01-26T07:35:41.305552Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log2_logMemsizeTooHigh.json", Total Files :: 1
2023-01-26T07:35:41.341853Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:41.342051Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:41.342055Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:41.342106Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:41.342108Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:41.342166Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:41.342239Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:41.342242Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2_logMemsizeTooHigh"::Istanbul::0
2023-01-26T07:35:41.342245Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log2_logMemsizeTooHigh.json"
2023-01-26T07:35:41.342248Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:41.342249Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:41.708295Z  INFO evm_eth_compliance::statetest::runner: UC : "log2_logMemsizeTooHigh"
2023-01-26T07:35:41.708309Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:41.708321Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:41.708327Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2_logMemsizeTooHigh"::Berlin::0
2023-01-26T07:35:41.708328Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log2_logMemsizeTooHigh.json"
2023-01-26T07:35:41.708331Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:41.708333Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:41.708455Z  INFO evm_eth_compliance::statetest::runner: UC : "log2_logMemsizeTooHigh"
2023-01-26T07:35:41.708459Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:41.708465Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:41.708467Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2_logMemsizeTooHigh"::London::0
2023-01-26T07:35:41.708469Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log2_logMemsizeTooHigh.json"
2023-01-26T07:35:41.708472Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:41.708473Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:41.708604Z  INFO evm_eth_compliance::statetest::runner: UC : "log2_logMemsizeTooHigh"
2023-01-26T07:35:41.708609Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:41.708614Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:41.708617Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2_logMemsizeTooHigh"::Merge::0
2023-01-26T07:35:41.708619Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log2_logMemsizeTooHigh.json"
2023-01-26T07:35:41.708622Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:41.708624Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:41.708731Z  INFO evm_eth_compliance::statetest::runner: UC : "log2_logMemsizeTooHigh"
2023-01-26T07:35:41.708736Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:41.710267Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:366.892478ms
2023-01-26T07:35:41.969537Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log2_logMemsizeZero.json", Total Files :: 1
2023-01-26T07:35:42.000342Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:42.000534Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:42.000537Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:42.000589Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:42.000591Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:42.000650Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:42.000720Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:42.000723Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2_logMemsizeZero"::Istanbul::0
2023-01-26T07:35:42.000726Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log2_logMemsizeZero.json"
2023-01-26T07:35:42.000729Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:42.000731Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:42.346311Z  INFO evm_eth_compliance::statetest::runner: UC : "log2_logMemsizeZero"
2023-01-26T07:35:42.346325Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:42.346336Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:42.346343Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2_logMemsizeZero"::Berlin::0
2023-01-26T07:35:42.346345Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log2_logMemsizeZero.json"
2023-01-26T07:35:42.346347Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:42.346349Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:42.346470Z  INFO evm_eth_compliance::statetest::runner: UC : "log2_logMemsizeZero"
2023-01-26T07:35:42.346474Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:42.346480Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:42.346483Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2_logMemsizeZero"::London::0
2023-01-26T07:35:42.346485Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log2_logMemsizeZero.json"
2023-01-26T07:35:42.346487Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:42.346488Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:42.346595Z  INFO evm_eth_compliance::statetest::runner: UC : "log2_logMemsizeZero"
2023-01-26T07:35:42.346599Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:42.346604Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:42.346607Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2_logMemsizeZero"::Merge::0
2023-01-26T07:35:42.346609Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log2_logMemsizeZero.json"
2023-01-26T07:35:42.346611Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:42.346612Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:42.346721Z  INFO evm_eth_compliance::statetest::runner: UC : "log2_logMemsizeZero"
2023-01-26T07:35:42.346727Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:42.348434Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:346.394945ms
2023-01-26T07:35:42.609095Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log2_nonEmptyMem.json", Total Files :: 1
2023-01-26T07:35:42.639364Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:42.639564Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:42.639567Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:42.639621Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:42.639623Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:42.639689Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:42.639767Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:42.639770Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2_nonEmptyMem"::Istanbul::0
2023-01-26T07:35:42.639773Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log2_nonEmptyMem.json"
2023-01-26T07:35:42.639776Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:42.639777Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:43.031381Z  INFO evm_eth_compliance::statetest::runner: UC : "log2_nonEmptyMem"
2023-01-26T07:35:43.031395Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:43.031406Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:43.031412Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2_nonEmptyMem"::Berlin::0
2023-01-26T07:35:43.031414Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log2_nonEmptyMem.json"
2023-01-26T07:35:43.031417Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:43.031418Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:43.031556Z  INFO evm_eth_compliance::statetest::runner: UC : "log2_nonEmptyMem"
2023-01-26T07:35:43.031560Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:43.031566Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:43.031569Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2_nonEmptyMem"::London::0
2023-01-26T07:35:43.031571Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log2_nonEmptyMem.json"
2023-01-26T07:35:43.031574Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:43.031575Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:43.031702Z  INFO evm_eth_compliance::statetest::runner: UC : "log2_nonEmptyMem"
2023-01-26T07:35:43.031706Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:43.031711Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:43.031714Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2_nonEmptyMem"::Merge::0
2023-01-26T07:35:43.031716Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log2_nonEmptyMem.json"
2023-01-26T07:35:43.031718Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:43.031721Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:43.031825Z  INFO evm_eth_compliance::statetest::runner: UC : "log2_nonEmptyMem"
2023-01-26T07:35:43.031829Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:43.033486Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:392.474656ms
2023-01-26T07:35:43.313254Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log2_nonEmptyMem_logMemSize1.json", Total Files :: 1
2023-01-26T07:35:43.343281Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:43.343491Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:43.343496Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:43.343549Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:43.343551Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:43.343610Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:43.343681Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:43.343686Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2_nonEmptyMem_logMemSize1"::Istanbul::0
2023-01-26T07:35:43.343689Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log2_nonEmptyMem_logMemSize1.json"
2023-01-26T07:35:43.343693Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:43.343695Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:43.683312Z  INFO evm_eth_compliance::statetest::runner: UC : "log2_nonEmptyMem_logMemSize1"
2023-01-26T07:35:43.683328Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:43.683339Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:43.683346Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2_nonEmptyMem_logMemSize1"::Berlin::0
2023-01-26T07:35:43.683348Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log2_nonEmptyMem_logMemSize1.json"
2023-01-26T07:35:43.683351Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:43.683353Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:43.683473Z  INFO evm_eth_compliance::statetest::runner: UC : "log2_nonEmptyMem_logMemSize1"
2023-01-26T07:35:43.683478Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:43.683483Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:43.683486Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2_nonEmptyMem_logMemSize1"::London::0
2023-01-26T07:35:43.683488Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log2_nonEmptyMem_logMemSize1.json"
2023-01-26T07:35:43.683491Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:43.683492Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:43.683598Z  INFO evm_eth_compliance::statetest::runner: UC : "log2_nonEmptyMem_logMemSize1"
2023-01-26T07:35:43.683602Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:43.683607Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:43.683611Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2_nonEmptyMem_logMemSize1"::Merge::0
2023-01-26T07:35:43.683613Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log2_nonEmptyMem_logMemSize1.json"
2023-01-26T07:35:43.683615Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:43.683617Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:43.683720Z  INFO evm_eth_compliance::statetest::runner: UC : "log2_nonEmptyMem_logMemSize1"
2023-01-26T07:35:43.683724Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:43.685278Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:340.453037ms
2023-01-26T07:35:43.971335Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log2_nonEmptyMem_logMemSize1_logMemStart31.json", Total Files :: 1
2023-01-26T07:35:44.029976Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:44.030203Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:44.030208Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:44.030263Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:44.030265Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:44.030329Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:44.030402Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:44.030406Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2_nonEmptyMem_logMemSize1_logMemStart31"::Istanbul::0
2023-01-26T07:35:44.030409Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log2_nonEmptyMem_logMemSize1_logMemStart31.json"
2023-01-26T07:35:44.030412Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:44.030414Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:44.394337Z  INFO evm_eth_compliance::statetest::runner: UC : "log2_nonEmptyMem_logMemSize1_logMemStart31"
2023-01-26T07:35:44.394353Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:44.394364Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:44.394372Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2_nonEmptyMem_logMemSize1_logMemStart31"::Berlin::0
2023-01-26T07:35:44.394374Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log2_nonEmptyMem_logMemSize1_logMemStart31.json"
2023-01-26T07:35:44.394378Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:44.394380Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:44.394518Z  INFO evm_eth_compliance::statetest::runner: UC : "log2_nonEmptyMem_logMemSize1_logMemStart31"
2023-01-26T07:35:44.394524Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:44.394532Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:44.394536Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2_nonEmptyMem_logMemSize1_logMemStart31"::London::0
2023-01-26T07:35:44.394539Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log2_nonEmptyMem_logMemSize1_logMemStart31.json"
2023-01-26T07:35:44.394542Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:44.394545Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:44.394680Z  INFO evm_eth_compliance::statetest::runner: UC : "log2_nonEmptyMem_logMemSize1_logMemStart31"
2023-01-26T07:35:44.394685Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:44.394692Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:44.394696Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2_nonEmptyMem_logMemSize1_logMemStart31"::Merge::0
2023-01-26T07:35:44.394699Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log2_nonEmptyMem_logMemSize1_logMemStart31.json"
2023-01-26T07:35:44.394703Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:44.394705Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:44.394820Z  INFO evm_eth_compliance::statetest::runner: UC : "log2_nonEmptyMem_logMemSize1_logMemStart31"
2023-01-26T07:35:44.394825Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:44.396426Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:364.861558ms
2023-01-26T07:35:44.674361Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log3_Caller.json", Total Files :: 1
2023-01-26T07:35:44.749047Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:44.749242Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:44.749246Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:44.749299Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:44.749301Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:44.749362Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:44.749433Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:44.749436Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_Caller"::Istanbul::0
2023-01-26T07:35:44.749439Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_Caller.json"
2023-01-26T07:35:44.749442Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:44.749444Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:45.109884Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_Caller"
2023-01-26T07:35:45.109899Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:45.109911Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:45.109919Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_Caller"::Berlin::0
2023-01-26T07:35:45.109921Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_Caller.json"
2023-01-26T07:35:45.109925Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:45.109927Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:45.110047Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_Caller"
2023-01-26T07:35:45.110052Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:45.110059Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:45.110062Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_Caller"::London::0
2023-01-26T07:35:45.110065Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_Caller.json"
2023-01-26T07:35:45.110068Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:45.110070Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:45.110202Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_Caller"
2023-01-26T07:35:45.110207Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:45.110213Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:45.110217Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_Caller"::Merge::0
2023-01-26T07:35:45.110219Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_Caller.json"
2023-01-26T07:35:45.110221Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:45.110223Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:45.110333Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_Caller"
2023-01-26T07:35:45.110337Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:45.111926Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:361.302387ms
2023-01-26T07:35:45.378398Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log3_MaxTopic.json", Total Files :: 1
2023-01-26T07:35:45.411592Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:45.411791Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:45.411795Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:45.411847Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:45.411849Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:45.411911Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:45.411985Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:45.411988Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_MaxTopic"::Istanbul::0
2023-01-26T07:35:45.411991Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_MaxTopic.json"
2023-01-26T07:35:45.411994Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:45.411995Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:45.769636Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_MaxTopic"
2023-01-26T07:35:45.769649Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:45.769660Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:45.769667Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_MaxTopic"::Berlin::0
2023-01-26T07:35:45.769669Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_MaxTopic.json"
2023-01-26T07:35:45.769672Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:45.769673Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:45.769805Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_MaxTopic"
2023-01-26T07:35:45.769809Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:45.769815Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:45.769817Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_MaxTopic"::London::0
2023-01-26T07:35:45.769819Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_MaxTopic.json"
2023-01-26T07:35:45.769821Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:45.769823Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:45.769951Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_MaxTopic"
2023-01-26T07:35:45.769955Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:45.769960Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:45.769962Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_MaxTopic"::Merge::0
2023-01-26T07:35:45.769964Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_MaxTopic.json"
2023-01-26T07:35:45.769966Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:45.769968Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:45.770076Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_MaxTopic"
2023-01-26T07:35:45.770080Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:45.771740Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:358.498531ms
2023-01-26T07:35:46.040113Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log3_PC.json", Total Files :: 1
2023-01-26T07:35:46.070305Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:46.070509Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:46.070514Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:46.070568Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:46.070571Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:46.070634Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:46.070709Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:46.070713Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_PC"::Istanbul::0
2023-01-26T07:35:46.070716Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_PC.json"
2023-01-26T07:35:46.070719Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:46.070721Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:46.460401Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_PC"
2023-01-26T07:35:46.460418Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:46.460429Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:46.460435Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_PC"::Berlin::0
2023-01-26T07:35:46.460436Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_PC.json"
2023-01-26T07:35:46.460439Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:46.460440Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:46.460584Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_PC"
2023-01-26T07:35:46.460588Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:46.460593Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:46.460596Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_PC"::London::0
2023-01-26T07:35:46.460598Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_PC.json"
2023-01-26T07:35:46.460600Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:46.460601Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:46.460713Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_PC"
2023-01-26T07:35:46.460718Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:46.460724Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:46.460726Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_PC"::Merge::0
2023-01-26T07:35:46.460728Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_PC.json"
2023-01-26T07:35:46.460730Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:46.460732Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:46.460842Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_PC"
2023-01-26T07:35:46.460846Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:46.462477Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:390.551374ms
2023-01-26T07:35:46.735248Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log3_emptyMem.json", Total Files :: 1
2023-01-26T07:35:46.800936Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:46.801128Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:46.801131Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:46.801181Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:46.801183Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:46.801242Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:46.801313Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:46.801316Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_emptyMem"::Istanbul::0
2023-01-26T07:35:46.801319Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_emptyMem.json"
2023-01-26T07:35:46.801322Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:46.801324Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:47.145297Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_emptyMem"
2023-01-26T07:35:47.145312Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:47.145322Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:47.145328Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_emptyMem"::Berlin::0
2023-01-26T07:35:47.145330Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_emptyMem.json"
2023-01-26T07:35:47.145332Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:47.145334Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:47.145450Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_emptyMem"
2023-01-26T07:35:47.145454Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:47.145460Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:47.145462Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_emptyMem"::London::0
2023-01-26T07:35:47.145464Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_emptyMem.json"
2023-01-26T07:35:47.145466Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:47.145468Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:47.145593Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_emptyMem"
2023-01-26T07:35:47.145596Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:47.145601Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:47.145604Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_emptyMem"::Merge::0
2023-01-26T07:35:47.145606Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_emptyMem.json"
2023-01-26T07:35:47.145608Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:47.145609Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:47.145713Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_emptyMem"
2023-01-26T07:35:47.145727Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:47.147563Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:344.800943ms
2023-01-26T07:35:47.421977Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log3_logMemStartTooHigh.json", Total Files :: 1
2023-01-26T07:35:47.451468Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:47.451665Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:47.451669Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:47.451721Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:47.451722Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:47.451782Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:47.451853Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:47.451857Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_logMemStartTooHigh"::Istanbul::0
2023-01-26T07:35:47.451859Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_logMemStartTooHigh.json"
2023-01-26T07:35:47.451862Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:47.451864Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:47.841963Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_logMemStartTooHigh"
2023-01-26T07:35:47.841979Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:47.841990Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:47.841996Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_logMemStartTooHigh"::Berlin::0
2023-01-26T07:35:47.841998Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_logMemStartTooHigh.json"
2023-01-26T07:35:47.842001Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:47.842003Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:47.842125Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_logMemStartTooHigh"
2023-01-26T07:35:47.842129Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:47.842135Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:47.842137Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_logMemStartTooHigh"::London::0
2023-01-26T07:35:47.842139Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_logMemStartTooHigh.json"
2023-01-26T07:35:47.842141Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:47.842143Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:47.842250Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_logMemStartTooHigh"
2023-01-26T07:35:47.842254Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:47.842259Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:47.842261Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_logMemStartTooHigh"::Merge::0
2023-01-26T07:35:47.842263Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_logMemStartTooHigh.json"
2023-01-26T07:35:47.842266Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:47.842267Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:47.842373Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_logMemStartTooHigh"
2023-01-26T07:35:47.842377Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:47.843989Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:390.918762ms
2023-01-26T07:35:48.123186Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log3_logMemsizeTooHigh.json", Total Files :: 1
2023-01-26T07:35:48.154212Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:48.154412Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:48.154416Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:48.154468Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:48.154470Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:48.154531Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:48.154603Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:48.154606Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_logMemsizeTooHigh"::Istanbul::0
2023-01-26T07:35:48.154609Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_logMemsizeTooHigh.json"
2023-01-26T07:35:48.154612Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:48.154614Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:48.506108Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_logMemsizeTooHigh"
2023-01-26T07:35:48.506123Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:48.506133Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:48.506141Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_logMemsizeTooHigh"::Berlin::0
2023-01-26T07:35:48.506143Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_logMemsizeTooHigh.json"
2023-01-26T07:35:48.506146Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:48.506147Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:48.506276Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_logMemsizeTooHigh"
2023-01-26T07:35:48.506280Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:48.506286Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:48.506289Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_logMemsizeTooHigh"::London::0
2023-01-26T07:35:48.506290Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_logMemsizeTooHigh.json"
2023-01-26T07:35:48.506293Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:48.506295Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:48.506402Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_logMemsizeTooHigh"
2023-01-26T07:35:48.506406Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:48.506413Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:48.506415Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_logMemsizeTooHigh"::Merge::0
2023-01-26T07:35:48.506417Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_logMemsizeTooHigh.json"
2023-01-26T07:35:48.506420Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:48.506422Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:48.506528Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_logMemsizeTooHigh"
2023-01-26T07:35:48.506532Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:48.508029Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:352.331544ms
2023-01-26T07:35:48.789122Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log3_logMemsizeZero.json", Total Files :: 1
2023-01-26T07:35:48.849441Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:48.849649Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:48.849653Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:48.849708Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:48.849711Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:48.849780Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:48.849857Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:48.849861Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_logMemsizeZero"::Istanbul::0
2023-01-26T07:35:48.849864Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_logMemsizeZero.json"
2023-01-26T07:35:48.849869Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:48.849871Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:49.237997Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_logMemsizeZero"
2023-01-26T07:35:49.238013Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:49.238024Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:49.238031Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_logMemsizeZero"::Berlin::0
2023-01-26T07:35:49.238033Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_logMemsizeZero.json"
2023-01-26T07:35:49.238035Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:49.238037Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:49.238158Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_logMemsizeZero"
2023-01-26T07:35:49.238163Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:49.238169Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:49.238171Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_logMemsizeZero"::London::0
2023-01-26T07:35:49.238173Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_logMemsizeZero.json"
2023-01-26T07:35:49.238175Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:49.238176Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:49.238281Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_logMemsizeZero"
2023-01-26T07:35:49.238285Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:49.238292Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:49.238294Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_logMemsizeZero"::Merge::0
2023-01-26T07:35:49.238296Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_logMemsizeZero.json"
2023-01-26T07:35:49.238298Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:49.238300Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:49.238403Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_logMemsizeZero"
2023-01-26T07:35:49.238408Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:49.239909Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:388.977069ms
2023-01-26T07:35:49.521820Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log3_nonEmptyMem.json", Total Files :: 1
2023-01-26T07:35:49.551756Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:49.551954Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:49.551958Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:49.552010Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:49.552012Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:49.552072Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:49.552150Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:49.552153Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_nonEmptyMem"::Istanbul::0
2023-01-26T07:35:49.552156Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_nonEmptyMem.json"
2023-01-26T07:35:49.552159Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:49.552161Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:49.907767Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_nonEmptyMem"
2023-01-26T07:35:49.907785Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:49.907797Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:49.907803Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_nonEmptyMem"::Berlin::0
2023-01-26T07:35:49.907806Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_nonEmptyMem.json"
2023-01-26T07:35:49.907811Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:49.907812Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:49.907940Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_nonEmptyMem"
2023-01-26T07:35:49.907945Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:49.907951Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:49.907953Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_nonEmptyMem"::London::0
2023-01-26T07:35:49.907955Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_nonEmptyMem.json"
2023-01-26T07:35:49.907958Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:49.907959Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:49.908087Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_nonEmptyMem"
2023-01-26T07:35:49.908091Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:49.908097Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:49.908099Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_nonEmptyMem"::Merge::0
2023-01-26T07:35:49.908101Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_nonEmptyMem.json"
2023-01-26T07:35:49.908104Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:49.908105Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:49.908212Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_nonEmptyMem"
2023-01-26T07:35:49.908217Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:49.909903Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:356.471072ms
2023-01-26T07:35:50.189461Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log3_nonEmptyMem_logMemSize1.json", Total Files :: 1
2023-01-26T07:35:50.220308Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:50.220521Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:50.220526Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:50.220581Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:50.220585Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:50.220650Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:50.220727Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:50.220731Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_nonEmptyMem_logMemSize1"::Istanbul::0
2023-01-26T07:35:50.220735Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_nonEmptyMem_logMemSize1.json"
2023-01-26T07:35:50.220739Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:50.220741Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:50.606973Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_nonEmptyMem_logMemSize1"
2023-01-26T07:35:50.606989Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:50.607001Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:50.607007Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_nonEmptyMem_logMemSize1"::Berlin::0
2023-01-26T07:35:50.607009Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_nonEmptyMem_logMemSize1.json"
2023-01-26T07:35:50.607012Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:50.607014Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:50.607137Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_nonEmptyMem_logMemSize1"
2023-01-26T07:35:50.607141Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:50.607148Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:50.607150Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_nonEmptyMem_logMemSize1"::London::0
2023-01-26T07:35:50.607152Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_nonEmptyMem_logMemSize1.json"
2023-01-26T07:35:50.607155Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:50.607156Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:50.607281Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_nonEmptyMem_logMemSize1"
2023-01-26T07:35:50.607286Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:50.607293Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:50.607295Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_nonEmptyMem_logMemSize1"::Merge::0
2023-01-26T07:35:50.607297Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_nonEmptyMem_logMemSize1.json"
2023-01-26T07:35:50.607300Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:50.607301Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:50.607406Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_nonEmptyMem_logMemSize1"
2023-01-26T07:35:50.607410Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:50.608974Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:387.112925ms
2023-01-26T07:35:50.886479Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log3_nonEmptyMem_logMemSize1_logMemStart31.json", Total Files :: 1
2023-01-26T07:35:50.950636Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:50.950829Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:50.950833Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:50.950882Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:50.950884Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:50.950944Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:50.951012Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:50.951015Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_nonEmptyMem_logMemSize1_logMemStart31"::Istanbul::0
2023-01-26T07:35:50.951018Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_nonEmptyMem_logMemSize1_logMemStart31.json"
2023-01-26T07:35:50.951022Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:50.951023Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:51.305781Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_nonEmptyMem_logMemSize1_logMemStart31"
2023-01-26T07:35:51.305797Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:51.305808Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:51.305815Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_nonEmptyMem_logMemSize1_logMemStart31"::Berlin::0
2023-01-26T07:35:51.305817Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_nonEmptyMem_logMemSize1_logMemStart31.json"
2023-01-26T07:35:51.305821Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:51.305822Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:51.305964Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_nonEmptyMem_logMemSize1_logMemStart31"
2023-01-26T07:35:51.305969Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:51.305974Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:51.305976Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_nonEmptyMem_logMemSize1_logMemStart31"::London::0
2023-01-26T07:35:51.305979Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_nonEmptyMem_logMemSize1_logMemStart31.json"
2023-01-26T07:35:51.305982Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:51.305983Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:51.306130Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_nonEmptyMem_logMemSize1_logMemStart31"
2023-01-26T07:35:51.306135Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:51.306140Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:51.306143Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3_nonEmptyMem_logMemSize1_logMemStart31"::Merge::0
2023-01-26T07:35:51.306146Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log3_nonEmptyMem_logMemSize1_logMemStart31.json"
2023-01-26T07:35:51.306148Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:51.306150Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:51.306256Z  INFO evm_eth_compliance::statetest::runner: UC : "log3_nonEmptyMem_logMemSize1_logMemStart31"
2023-01-26T07:35:51.306260Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:51.307905Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:355.633406ms
2023-01-26T07:35:51.575250Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log4_Caller.json", Total Files :: 1
2023-01-26T07:35:51.611459Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:51.611652Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:51.611656Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:51.611708Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:51.611710Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:51.611769Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:51.611840Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:51.611843Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_Caller"::Istanbul::0
2023-01-26T07:35:51.611846Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_Caller.json"
2023-01-26T07:35:51.611849Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:51.611850Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:52.001470Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_Caller"
2023-01-26T07:35:52.001485Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:52.001497Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:52.001502Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_Caller"::Berlin::0
2023-01-26T07:35:52.001504Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_Caller.json"
2023-01-26T07:35:52.001507Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:52.001508Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:52.001623Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_Caller"
2023-01-26T07:35:52.001627Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:52.001634Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:52.001636Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_Caller"::London::0
2023-01-26T07:35:52.001638Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_Caller.json"
2023-01-26T07:35:52.001640Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:52.001642Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:52.001755Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_Caller"
2023-01-26T07:35:52.001759Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:52.001764Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:52.001766Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_Caller"::Merge::0
2023-01-26T07:35:52.001768Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_Caller.json"
2023-01-26T07:35:52.001770Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:52.001771Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:52.001872Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_Caller"
2023-01-26T07:35:52.001876Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:52.003499Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:390.427115ms
2023-01-26T07:35:52.271272Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log4_MaxTopic.json", Total Files :: 1
2023-01-26T07:35:52.300978Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:52.301171Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:52.301174Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:52.301227Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:52.301229Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:52.301287Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:52.301359Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:52.301362Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_MaxTopic"::Istanbul::0
2023-01-26T07:35:52.301365Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_MaxTopic.json"
2023-01-26T07:35:52.301368Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:52.301369Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:52.673666Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_MaxTopic"
2023-01-26T07:35:52.673681Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:52.673692Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:52.673699Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_MaxTopic"::Berlin::0
2023-01-26T07:35:52.673700Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_MaxTopic.json"
2023-01-26T07:35:52.673703Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:52.673704Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:52.673837Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_MaxTopic"
2023-01-26T07:35:52.673842Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:52.673847Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:52.673850Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_MaxTopic"::London::0
2023-01-26T07:35:52.673852Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_MaxTopic.json"
2023-01-26T07:35:52.673854Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:52.673856Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:52.673981Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_MaxTopic"
2023-01-26T07:35:52.673985Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:52.673991Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:52.673993Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_MaxTopic"::Merge::0
2023-01-26T07:35:52.673995Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_MaxTopic.json"
2023-01-26T07:35:52.673997Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:52.673999Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:52.674105Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_MaxTopic"
2023-01-26T07:35:52.674109Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:52.675779Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:373.141477ms
2023-01-26T07:35:52.975930Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log4_PC.json", Total Files :: 1
2023-01-26T07:35:53.006529Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:53.006727Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:53.006732Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:53.006785Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:53.006787Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:53.006849Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:53.006922Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:53.006925Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_PC"::Istanbul::0
2023-01-26T07:35:53.006928Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_PC.json"
2023-01-26T07:35:53.006932Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:53.006933Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:53.357509Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_PC"
2023-01-26T07:35:53.357525Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:53.357540Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:53.357547Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_PC"::Berlin::0
2023-01-26T07:35:53.357549Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_PC.json"
2023-01-26T07:35:53.357552Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:53.357553Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:53.357677Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_PC"
2023-01-26T07:35:53.357683Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:53.357689Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:53.357692Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_PC"::London::0
2023-01-26T07:35:53.357693Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_PC.json"
2023-01-26T07:35:53.357696Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:53.357697Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:53.357813Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_PC"
2023-01-26T07:35:53.357818Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:53.357824Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:53.357827Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_PC"::Merge::0
2023-01-26T07:35:53.357828Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_PC.json"
2023-01-26T07:35:53.357831Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:53.357832Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:53.357938Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_PC"
2023-01-26T07:35:53.357942Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:53.359722Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:351.425718ms
2023-01-26T07:35:53.618519Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log4_emptyMem.json", Total Files :: 1
2023-01-26T07:35:53.656490Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:53.656718Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:53.656722Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:53.656782Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:53.656784Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:53.656846Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:53.656928Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:53.656931Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_emptyMem"::Istanbul::0
2023-01-26T07:35:53.656934Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_emptyMem.json"
2023-01-26T07:35:53.656937Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:53.656938Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:54.022379Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_emptyMem"
2023-01-26T07:35:54.022393Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:54.022405Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:54.022411Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_emptyMem"::Berlin::0
2023-01-26T07:35:54.022412Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_emptyMem.json"
2023-01-26T07:35:54.022415Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:54.022417Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:54.022544Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_emptyMem"
2023-01-26T07:35:54.022548Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:54.022554Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:54.022558Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_emptyMem"::London::0
2023-01-26T07:35:54.022560Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_emptyMem.json"
2023-01-26T07:35:54.022562Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:54.022564Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:54.022674Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_emptyMem"
2023-01-26T07:35:54.022678Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:54.022683Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:54.022685Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_emptyMem"::Merge::0
2023-01-26T07:35:54.022687Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_emptyMem.json"
2023-01-26T07:35:54.022689Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:54.022690Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:54.022795Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_emptyMem"
2023-01-26T07:35:54.022800Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:54.024321Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:366.321854ms
2023-01-26T07:35:54.302113Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log4_logMemStartTooHigh.json", Total Files :: 1
2023-01-26T07:35:54.331576Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:54.331785Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:54.331789Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:54.331845Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:54.331848Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:54.331910Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:54.331983Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:54.331987Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_logMemStartTooHigh"::Istanbul::0
2023-01-26T07:35:54.331990Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_logMemStartTooHigh.json"
2023-01-26T07:35:54.331993Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:54.331994Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:54.691241Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_logMemStartTooHigh"
2023-01-26T07:35:54.691258Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:54.691269Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:54.691276Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_logMemStartTooHigh"::Berlin::0
2023-01-26T07:35:54.691277Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_logMemStartTooHigh.json"
2023-01-26T07:35:54.691280Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:54.691282Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:54.691406Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_logMemStartTooHigh"
2023-01-26T07:35:54.691411Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:54.691416Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:54.691420Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_logMemStartTooHigh"::London::0
2023-01-26T07:35:54.691422Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_logMemStartTooHigh.json"
2023-01-26T07:35:54.691424Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:54.691426Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:54.691537Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_logMemStartTooHigh"
2023-01-26T07:35:54.691542Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:54.691547Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:54.691550Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_logMemStartTooHigh"::Merge::0
2023-01-26T07:35:54.691552Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_logMemStartTooHigh.json"
2023-01-26T07:35:54.691554Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:54.691555Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:54.691664Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_logMemStartTooHigh"
2023-01-26T07:35:54.691668Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:54.693206Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:360.102767ms
2023-01-26T07:35:54.958954Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log4_logMemsizeTooHigh.json", Total Files :: 1
2023-01-26T07:35:55.018302Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:55.018497Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:55.018501Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:55.018553Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:55.018555Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:55.018614Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:55.018687Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:55.018690Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_logMemsizeTooHigh"::Istanbul::0
2023-01-26T07:35:55.018694Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_logMemsizeTooHigh.json"
2023-01-26T07:35:55.018697Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:55.018698Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:55.357230Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_logMemsizeTooHigh"
2023-01-26T07:35:55.357245Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:55.357257Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:55.357263Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_logMemsizeTooHigh"::Berlin::0
2023-01-26T07:35:55.357265Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_logMemsizeTooHigh.json"
2023-01-26T07:35:55.357268Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:55.357269Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:55.357385Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_logMemsizeTooHigh"
2023-01-26T07:35:55.357389Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:55.357395Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:55.357397Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_logMemsizeTooHigh"::London::0
2023-01-26T07:35:55.357399Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_logMemsizeTooHigh.json"
2023-01-26T07:35:55.357402Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:55.357403Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:55.357508Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_logMemsizeTooHigh"
2023-01-26T07:35:55.357513Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:55.357518Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:55.357521Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_logMemsizeTooHigh"::Merge::0
2023-01-26T07:35:55.357523Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_logMemsizeTooHigh.json"
2023-01-26T07:35:55.357525Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:55.357527Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:55.357630Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_logMemsizeTooHigh"
2023-01-26T07:35:55.357634Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:55.359133Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:339.341073ms
2023-01-26T07:35:55.615651Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log4_logMemsizeZero.json", Total Files :: 1
2023-01-26T07:35:55.646013Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:55.646218Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:55.646222Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:55.646276Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:55.646278Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:55.646340Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:55.646413Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:55.646417Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_logMemsizeZero"::Istanbul::0
2023-01-26T07:35:55.646420Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_logMemsizeZero.json"
2023-01-26T07:35:55.646423Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:55.646425Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:55.990326Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_logMemsizeZero"
2023-01-26T07:35:55.990341Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:55.990352Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:55.990359Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_logMemsizeZero"::Berlin::0
2023-01-26T07:35:55.990360Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_logMemsizeZero.json"
2023-01-26T07:35:55.990363Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:55.990365Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:55.990482Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_logMemsizeZero"
2023-01-26T07:35:55.990487Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:55.990492Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:55.990495Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_logMemsizeZero"::London::0
2023-01-26T07:35:55.990496Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_logMemsizeZero.json"
2023-01-26T07:35:55.990499Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:55.990500Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:55.990627Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_logMemsizeZero"
2023-01-26T07:35:55.990632Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:55.990637Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:55.990641Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_logMemsizeZero"::Merge::0
2023-01-26T07:35:55.990642Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_logMemsizeZero.json"
2023-01-26T07:35:55.990645Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:55.990646Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:55.990751Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_logMemsizeZero"
2023-01-26T07:35:55.990756Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:55.992135Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:344.754028ms
2023-01-26T07:35:56.275510Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log4_nonEmptyMem.json", Total Files :: 1
2023-01-26T07:35:56.306779Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:56.306997Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:56.307001Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:56.307056Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:56.307058Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:56.307121Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:56.307201Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:56.307204Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_nonEmptyMem"::Istanbul::0
2023-01-26T07:35:56.307207Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_nonEmptyMem.json"
2023-01-26T07:35:56.307211Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:56.307213Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:56.653783Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_nonEmptyMem"
2023-01-26T07:35:56.653797Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:56.653809Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:56.653815Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_nonEmptyMem"::Berlin::0
2023-01-26T07:35:56.653817Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_nonEmptyMem.json"
2023-01-26T07:35:56.653820Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:56.653821Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:56.653946Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_nonEmptyMem"
2023-01-26T07:35:56.653950Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:56.653956Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:56.653958Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_nonEmptyMem"::London::0
2023-01-26T07:35:56.653960Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_nonEmptyMem.json"
2023-01-26T07:35:56.653963Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:56.653965Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:56.654084Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_nonEmptyMem"
2023-01-26T07:35:56.654089Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:56.654094Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:56.654097Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_nonEmptyMem"::Merge::0
2023-01-26T07:35:56.654099Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_nonEmptyMem.json"
2023-01-26T07:35:56.654101Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:56.654103Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:56.654212Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_nonEmptyMem"
2023-01-26T07:35:56.654216Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:56.656003Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:347.447625ms
2023-01-26T07:35:56.929764Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log4_nonEmptyMem_logMemSize1.json", Total Files :: 1
2023-01-26T07:35:56.960743Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:56.960941Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:56.960945Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:56.960996Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:56.960999Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:56.961060Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:56.961131Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:56.961134Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_nonEmptyMem_logMemSize1"::Istanbul::0
2023-01-26T07:35:56.961137Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_nonEmptyMem_logMemSize1.json"
2023-01-26T07:35:56.961140Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:56.961141Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:57.373933Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_nonEmptyMem_logMemSize1"
2023-01-26T07:35:57.373951Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:57.373963Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:57.373969Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_nonEmptyMem_logMemSize1"::Berlin::0
2023-01-26T07:35:57.373971Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_nonEmptyMem_logMemSize1.json"
2023-01-26T07:35:57.373974Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:57.373975Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:57.374096Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_nonEmptyMem_logMemSize1"
2023-01-26T07:35:57.374100Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:57.374105Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:57.374108Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_nonEmptyMem_logMemSize1"::London::0
2023-01-26T07:35:57.374110Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_nonEmptyMem_logMemSize1.json"
2023-01-26T07:35:57.374113Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:57.374114Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:57.374216Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_nonEmptyMem_logMemSize1"
2023-01-26T07:35:57.374220Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:57.374225Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:57.374228Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_nonEmptyMem_logMemSize1"::Merge::0
2023-01-26T07:35:57.374230Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_nonEmptyMem_logMemSize1.json"
2023-01-26T07:35:57.374233Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:57.374234Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:57.374335Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_nonEmptyMem_logMemSize1"
2023-01-26T07:35:57.374339Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:57.375721Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:413.605899ms
2023-01-26T07:35:57.637628Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/log4_nonEmptyMem_logMemSize1_logMemStart31.json", Total Files :: 1
2023-01-26T07:35:57.666680Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:57.666866Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:57.666869Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:57.666920Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:57.666922Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:57.666980Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:57.667050Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:57.667053Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_nonEmptyMem_logMemSize1_logMemStart31"::Istanbul::0
2023-01-26T07:35:57.667056Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_nonEmptyMem_logMemSize1_logMemStart31.json"
2023-01-26T07:35:57.667060Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:57.667061Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:58.001062Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_nonEmptyMem_logMemSize1_logMemStart31"
2023-01-26T07:35:58.001078Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:58.001093Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:58.001102Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_nonEmptyMem_logMemSize1_logMemStart31"::Berlin::0
2023-01-26T07:35:58.001105Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_nonEmptyMem_logMemSize1_logMemStart31.json"
2023-01-26T07:35:58.001109Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:58.001111Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:58.001243Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_nonEmptyMem_logMemSize1_logMemStart31"
2023-01-26T07:35:58.001250Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:58.001258Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:58.001261Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_nonEmptyMem_logMemSize1_logMemStart31"::London::0
2023-01-26T07:35:58.001263Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_nonEmptyMem_logMemSize1_logMemStart31.json"
2023-01-26T07:35:58.001265Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:58.001267Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:58.001410Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_nonEmptyMem_logMemSize1_logMemStart31"
2023-01-26T07:35:58.001415Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:58.001421Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:58.001424Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log4_nonEmptyMem_logMemSize1_logMemStart31"::Merge::0
2023-01-26T07:35:58.001426Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/log4_nonEmptyMem_logMemSize1_logMemStart31.json"
2023-01-26T07:35:58.001430Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:58.001431Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:58.001538Z  INFO evm_eth_compliance::statetest::runner: UC : "log4_nonEmptyMem_logMemSize1_logMemStart31"
2023-01-26T07:35:58.001542Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1711225,
    events_root: None,
}
2023-01-26T07:35:58.003143Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:334.873899ms
2023-01-26T07:35:58.282753Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stLogTests/logInOOG_Call.json", Total Files :: 1
2023-01-26T07:35:58.312924Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-26T07:35:58.313125Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:58.313129Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-26T07:35:58.313184Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:58.313186Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-26T07:35:58.313247Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-26T07:35:58.313321Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-26T07:35:58.313324Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "logInOOG_Call"::Istanbul::0
2023-01-26T07:35:58.313327Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/logInOOG_Call.json"
2023-01-26T07:35:58.313330Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:58.313332Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:58.649071Z  INFO evm_eth_compliance::statetest::runner: UC : "logInOOG_Call"
2023-01-26T07:35:58.649088Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1810159,
    events_root: None,
}
2023-01-26T07:35:58.649100Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-26T07:35:58.649106Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "logInOOG_Call"::Berlin::0
2023-01-26T07:35:58.649108Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/logInOOG_Call.json"
2023-01-26T07:35:58.649111Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:58.649112Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:58.649236Z  INFO evm_eth_compliance::statetest::runner: UC : "logInOOG_Call"
2023-01-26T07:35:58.649241Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1810159,
    events_root: None,
}
2023-01-26T07:35:58.649246Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-26T07:35:58.649249Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "logInOOG_Call"::London::0
2023-01-26T07:35:58.649250Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/logInOOG_Call.json"
2023-01-26T07:35:58.649253Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:58.649254Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:58.649366Z  INFO evm_eth_compliance::statetest::runner: UC : "logInOOG_Call"
2023-01-26T07:35:58.649370Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1810159,
    events_root: None,
}
2023-01-26T07:35:58.649375Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-26T07:35:58.649378Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "logInOOG_Call"::Merge::0
2023-01-26T07:35:58.649379Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stLogTests/logInOOG_Call.json"
2023-01-26T07:35:58.649382Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-26T07:35:58.649383Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-26T07:35:58.649493Z  INFO evm_eth_compliance::statetest::runner: UC : "logInOOG_Call"
2023-01-26T07:35:58.649497Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1810159,
    events_root: None,
}
2023-01-26T07:35:58.651082Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:336.583452ms
```