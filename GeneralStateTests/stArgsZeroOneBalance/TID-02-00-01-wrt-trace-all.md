> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stArgsZeroOneBalance

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance \
	cargo run --release \
	-- \
	statetest
```

> For Review

* Following use-cases are failed.

- Hit with error `EVM_CONTRACT_UNDEFINED_INSTRUCTION` (ExitCode::35)

| Test ID | Use-Case |
| --- | --- |
| TID-02-06 | callcodeNonConst |
| TID-02-21 | jumpNonConst |

> Execution Trace

```
2023-01-27T07:48:43.992504Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addNonConst.json", Total Files :: 1
2023-01-27T07:48:44.051314Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:48:44.051455Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:44.051459Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:48:44.051513Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:44.051586Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:44.051589Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addNonConst"::Istanbul::0
2023-01-27T07:48:44.051592Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addNonConst.json"
2023-01-27T07:48:44.051595Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:44.051597Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:44.407769Z  INFO evm_eth_compliance::statetest::runner: UC : "addNonConst"
2023-01-27T07:48:44.407785Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618944,
    events_root: None,
}
2023-01-27T07:48:44.407796Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:44.407801Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addNonConst"::Istanbul::0
2023-01-27T07:48:44.407802Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addNonConst.json"
2023-01-27T07:48:44.407805Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:44.407806Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:44.407915Z  INFO evm_eth_compliance::statetest::runner: UC : "addNonConst"
2023-01-27T07:48:44.407919Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618944,
    events_root: None,
}
2023-01-27T07:48:44.407925Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:44.407927Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addNonConst"::Berlin::0
2023-01-27T07:48:44.407929Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addNonConst.json"
2023-01-27T07:48:44.407932Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:44.407933Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:44.408026Z  INFO evm_eth_compliance::statetest::runner: UC : "addNonConst"
2023-01-27T07:48:44.408030Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618944,
    events_root: None,
}
2023-01-27T07:48:44.408035Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:44.408037Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addNonConst"::Berlin::0
2023-01-27T07:48:44.408038Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addNonConst.json"
2023-01-27T07:48:44.408041Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:44.408042Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:44.408139Z  INFO evm_eth_compliance::statetest::runner: UC : "addNonConst"
2023-01-27T07:48:44.408143Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618944,
    events_root: None,
}
2023-01-27T07:48:44.408148Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:44.408150Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addNonConst"::London::0
2023-01-27T07:48:44.408152Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addNonConst.json"
2023-01-27T07:48:44.408154Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:44.408156Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:44.408246Z  INFO evm_eth_compliance::statetest::runner: UC : "addNonConst"
2023-01-27T07:48:44.408250Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618944,
    events_root: None,
}
2023-01-27T07:48:44.408255Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:44.408257Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addNonConst"::London::0
2023-01-27T07:48:44.408258Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addNonConst.json"
2023-01-27T07:48:44.408261Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:44.408262Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:44.408354Z  INFO evm_eth_compliance::statetest::runner: UC : "addNonConst"
2023-01-27T07:48:44.408358Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618944,
    events_root: None,
}
2023-01-27T07:48:44.408363Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:44.408365Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addNonConst"::Merge::0
2023-01-27T07:48:44.408367Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addNonConst.json"
2023-01-27T07:48:44.408369Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:44.408370Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:44.408461Z  INFO evm_eth_compliance::statetest::runner: UC : "addNonConst"
2023-01-27T07:48:44.408465Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618944,
    events_root: None,
}
2023-01-27T07:48:44.408470Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:44.408471Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addNonConst"::Merge::0
2023-01-27T07:48:44.408473Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addNonConst.json"
2023-01-27T07:48:44.408476Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:44.408477Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:44.408568Z  INFO evm_eth_compliance::statetest::runner: UC : "addNonConst"
2023-01-27T07:48:44.408573Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618944,
    events_root: None,
}
2023-01-27T07:48:44.410111Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:357.268623ms
2023-01-27T07:48:44.693484Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addmodNonConst.json", Total Files :: 1
2023-01-27T07:48:44.731108Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:48:44.731242Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:44.731246Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:48:44.731299Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:44.731370Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:44.731373Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmodNonConst"::Istanbul::0
2023-01-27T07:48:44.731376Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addmodNonConst.json"
2023-01-27T07:48:44.731380Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:44.731381Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:45.101248Z  INFO evm_eth_compliance::statetest::runner: UC : "addmodNonConst"
2023-01-27T07:48:45.101268Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1664627,
    events_root: None,
}
2023-01-27T07:48:45.101281Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:45.101285Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmodNonConst"::Istanbul::0
2023-01-27T07:48:45.101287Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addmodNonConst.json"
2023-01-27T07:48:45.101291Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:45.101292Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:45.101452Z  INFO evm_eth_compliance::statetest::runner: UC : "addmodNonConst"
2023-01-27T07:48:45.101457Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1664627,
    events_root: None,
}
2023-01-27T07:48:45.101462Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:45.101464Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmodNonConst"::Berlin::0
2023-01-27T07:48:45.101466Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addmodNonConst.json"
2023-01-27T07:48:45.101468Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:45.101469Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:45.101568Z  INFO evm_eth_compliance::statetest::runner: UC : "addmodNonConst"
2023-01-27T07:48:45.101573Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1664627,
    events_root: None,
}
2023-01-27T07:48:45.101579Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:45.101580Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmodNonConst"::Berlin::0
2023-01-27T07:48:45.101582Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addmodNonConst.json"
2023-01-27T07:48:45.101585Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:45.101586Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:45.101682Z  INFO evm_eth_compliance::statetest::runner: UC : "addmodNonConst"
2023-01-27T07:48:45.101686Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1664627,
    events_root: None,
}
2023-01-27T07:48:45.101692Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:45.101695Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmodNonConst"::London::0
2023-01-27T07:48:45.101697Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addmodNonConst.json"
2023-01-27T07:48:45.101699Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:45.101701Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:45.101795Z  INFO evm_eth_compliance::statetest::runner: UC : "addmodNonConst"
2023-01-27T07:48:45.101799Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1664627,
    events_root: None,
}
2023-01-27T07:48:45.101805Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:45.101807Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmodNonConst"::London::0
2023-01-27T07:48:45.101808Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addmodNonConst.json"
2023-01-27T07:48:45.101811Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:45.101813Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:45.101909Z  INFO evm_eth_compliance::statetest::runner: UC : "addmodNonConst"
2023-01-27T07:48:45.101914Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1664627,
    events_root: None,
}
2023-01-27T07:48:45.101919Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:45.101920Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmodNonConst"::Merge::0
2023-01-27T07:48:45.101922Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addmodNonConst.json"
2023-01-27T07:48:45.101924Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:45.101926Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:45.102031Z  INFO evm_eth_compliance::statetest::runner: UC : "addmodNonConst"
2023-01-27T07:48:45.102037Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1664627,
    events_root: None,
}
2023-01-27T07:48:45.102044Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:45.102046Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "addmodNonConst"::Merge::0
2023-01-27T07:48:45.102049Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/addmodNonConst.json"
2023-01-27T07:48:45.102053Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:45.102054Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:45.102160Z  INFO evm_eth_compliance::statetest::runner: UC : "addmodNonConst"
2023-01-27T07:48:45.102164Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1664627,
    events_root: None,
}
2023-01-27T07:48:45.103845Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:371.065571ms
2023-01-27T07:48:45.372078Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/andNonConst.json", Total Files :: 1
2023-01-27T07:48:45.434313Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:48:45.434486Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:45.434492Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:48:45.434557Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:45.434633Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:45.434636Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "andNonConst"::Istanbul::0
2023-01-27T07:48:45.434639Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/andNonConst.json"
2023-01-27T07:48:45.434642Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:45.434644Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:45.822731Z  INFO evm_eth_compliance::statetest::runner: UC : "andNonConst"
2023-01-27T07:48:45.822749Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618736,
    events_root: None,
}
2023-01-27T07:48:45.822760Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:45.822764Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "andNonConst"::Istanbul::0
2023-01-27T07:48:45.822765Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/andNonConst.json"
2023-01-27T07:48:45.822768Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:45.822770Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:45.822899Z  INFO evm_eth_compliance::statetest::runner: UC : "andNonConst"
2023-01-27T07:48:45.822903Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618736,
    events_root: None,
}
2023-01-27T07:48:45.822910Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:45.822912Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "andNonConst"::Berlin::0
2023-01-27T07:48:45.822914Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/andNonConst.json"
2023-01-27T07:48:45.822917Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:45.822919Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:45.823011Z  INFO evm_eth_compliance::statetest::runner: UC : "andNonConst"
2023-01-27T07:48:45.823015Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618736,
    events_root: None,
}
2023-01-27T07:48:45.823020Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:45.823022Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "andNonConst"::Berlin::0
2023-01-27T07:48:45.823024Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/andNonConst.json"
2023-01-27T07:48:45.823028Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:45.823030Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:45.823121Z  INFO evm_eth_compliance::statetest::runner: UC : "andNonConst"
2023-01-27T07:48:45.823125Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618736,
    events_root: None,
}
2023-01-27T07:48:45.823130Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:45.823132Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "andNonConst"::London::0
2023-01-27T07:48:45.823133Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/andNonConst.json"
2023-01-27T07:48:45.823136Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:45.823137Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:45.823247Z  INFO evm_eth_compliance::statetest::runner: UC : "andNonConst"
2023-01-27T07:48:45.823252Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618736,
    events_root: None,
}
2023-01-27T07:48:45.823258Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:45.823260Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "andNonConst"::London::0
2023-01-27T07:48:45.823263Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/andNonConst.json"
2023-01-27T07:48:45.823266Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:45.823268Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:45.823367Z  INFO evm_eth_compliance::statetest::runner: UC : "andNonConst"
2023-01-27T07:48:45.823371Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618736,
    events_root: None,
}
2023-01-27T07:48:45.823376Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:45.823378Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "andNonConst"::Merge::0
2023-01-27T07:48:45.823380Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/andNonConst.json"
2023-01-27T07:48:45.823383Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:45.823384Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:45.823475Z  INFO evm_eth_compliance::statetest::runner: UC : "andNonConst"
2023-01-27T07:48:45.823479Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618736,
    events_root: None,
}
2023-01-27T07:48:45.823484Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:45.823486Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "andNonConst"::Merge::0
2023-01-27T07:48:45.823487Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/andNonConst.json"
2023-01-27T07:48:45.823490Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:45.823491Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:45.823581Z  INFO evm_eth_compliance::statetest::runner: UC : "andNonConst"
2023-01-27T07:48:45.823584Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618736,
    events_root: None,
}
2023-01-27T07:48:45.825306Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:389.281031ms
2023-01-27T07:48:46.100317Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/balanceNonConst.json", Total Files :: 1
2023-01-27T07:48:46.142794Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:48:46.142936Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:46.142940Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:48:46.142996Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:46.143071Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:46.143075Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "balanceNonConst"::Istanbul::0
2023-01-27T07:48:46.143077Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/balanceNonConst.json"
2023-01-27T07:48:46.143081Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:46.143083Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:46.523714Z  INFO evm_eth_compliance::statetest::runner: UC : "balanceNonConst"
2023-01-27T07:48:46.523731Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1598783,
    events_root: None,
}
2023-01-27T07:48:46.523743Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:46.523748Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "balanceNonConst"::Istanbul::0
2023-01-27T07:48:46.523750Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/balanceNonConst.json"
2023-01-27T07:48:46.523754Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:46.523756Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:46.523901Z  INFO evm_eth_compliance::statetest::runner: UC : "balanceNonConst"
2023-01-27T07:48:46.523905Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1598783,
    events_root: None,
}
2023-01-27T07:48:46.523912Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:46.523915Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "balanceNonConst"::Berlin::0
2023-01-27T07:48:46.523917Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/balanceNonConst.json"
2023-01-27T07:48:46.523920Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:46.523922Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:46.524033Z  INFO evm_eth_compliance::statetest::runner: UC : "balanceNonConst"
2023-01-27T07:48:46.524038Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1598783,
    events_root: None,
}
2023-01-27T07:48:46.524044Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:46.524047Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "balanceNonConst"::Berlin::0
2023-01-27T07:48:46.524050Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/balanceNonConst.json"
2023-01-27T07:48:46.524053Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:46.524055Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:46.524173Z  INFO evm_eth_compliance::statetest::runner: UC : "balanceNonConst"
2023-01-27T07:48:46.524177Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1598783,
    events_root: None,
}
2023-01-27T07:48:46.524184Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:46.524186Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "balanceNonConst"::London::0
2023-01-27T07:48:46.524189Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/balanceNonConst.json"
2023-01-27T07:48:46.524192Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:46.524194Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:46.524305Z  INFO evm_eth_compliance::statetest::runner: UC : "balanceNonConst"
2023-01-27T07:48:46.524309Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1598783,
    events_root: None,
}
2023-01-27T07:48:46.524315Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:46.524318Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "balanceNonConst"::London::0
2023-01-27T07:48:46.524321Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/balanceNonConst.json"
2023-01-27T07:48:46.524325Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:46.524327Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:46.524436Z  INFO evm_eth_compliance::statetest::runner: UC : "balanceNonConst"
2023-01-27T07:48:46.524440Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1598783,
    events_root: None,
}
2023-01-27T07:48:46.524446Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:46.524449Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "balanceNonConst"::Merge::0
2023-01-27T07:48:46.524452Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/balanceNonConst.json"
2023-01-27T07:48:46.524455Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:46.524457Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:46.524565Z  INFO evm_eth_compliance::statetest::runner: UC : "balanceNonConst"
2023-01-27T07:48:46.524570Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1598783,
    events_root: None,
}
2023-01-27T07:48:46.524576Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:46.524578Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "balanceNonConst"::Merge::0
2023-01-27T07:48:46.524581Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/balanceNonConst.json"
2023-01-27T07:48:46.524584Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:46.524587Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:46.524694Z  INFO evm_eth_compliance::statetest::runner: UC : "balanceNonConst"
2023-01-27T07:48:46.524699Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1598783,
    events_root: None,
}
2023-01-27T07:48:46.526342Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:381.916451ms
2023-01-27T07:48:46.817727Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/byteNonConst.json", Total Files :: 1
2023-01-27T07:48:46.877343Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:48:46.877478Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:46.877482Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:48:46.877536Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:46.877607Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:46.877609Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byteNonConst"::Istanbul::0
2023-01-27T07:48:46.877612Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/byteNonConst.json"
2023-01-27T07:48:46.877615Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:46.877617Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:47.242986Z  INFO evm_eth_compliance::statetest::runner: UC : "byteNonConst"
2023-01-27T07:48:47.243004Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1619056,
    events_root: None,
}
2023-01-27T07:48:47.243018Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:47.243022Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byteNonConst"::Istanbul::0
2023-01-27T07:48:47.243025Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/byteNonConst.json"
2023-01-27T07:48:47.243029Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:47.243033Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:47.243191Z  INFO evm_eth_compliance::statetest::runner: UC : "byteNonConst"
2023-01-27T07:48:47.243195Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1619056,
    events_root: None,
}
2023-01-27T07:48:47.243202Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:47.243205Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byteNonConst"::Berlin::0
2023-01-27T07:48:47.243208Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/byteNonConst.json"
2023-01-27T07:48:47.243211Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:47.243213Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:47.243333Z  INFO evm_eth_compliance::statetest::runner: UC : "byteNonConst"
2023-01-27T07:48:47.243338Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1619056,
    events_root: None,
}
2023-01-27T07:48:47.243345Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:47.243348Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byteNonConst"::Berlin::0
2023-01-27T07:48:47.243350Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/byteNonConst.json"
2023-01-27T07:48:47.243354Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:47.243356Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:47.243477Z  INFO evm_eth_compliance::statetest::runner: UC : "byteNonConst"
2023-01-27T07:48:47.243482Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1619056,
    events_root: None,
}
2023-01-27T07:48:47.243489Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:47.243492Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byteNonConst"::London::0
2023-01-27T07:48:47.243495Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/byteNonConst.json"
2023-01-27T07:48:47.243498Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:47.243500Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:47.243623Z  INFO evm_eth_compliance::statetest::runner: UC : "byteNonConst"
2023-01-27T07:48:47.243628Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1619056,
    events_root: None,
}
2023-01-27T07:48:47.243635Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:47.243638Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byteNonConst"::London::0
2023-01-27T07:48:47.243641Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/byteNonConst.json"
2023-01-27T07:48:47.243646Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:47.243647Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:47.243769Z  INFO evm_eth_compliance::statetest::runner: UC : "byteNonConst"
2023-01-27T07:48:47.243773Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1619056,
    events_root: None,
}
2023-01-27T07:48:47.243780Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:47.243783Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byteNonConst"::Merge::0
2023-01-27T07:48:47.243785Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/byteNonConst.json"
2023-01-27T07:48:47.243789Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:47.243791Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:47.243923Z  INFO evm_eth_compliance::statetest::runner: UC : "byteNonConst"
2023-01-27T07:48:47.243928Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1619056,
    events_root: None,
}
2023-01-27T07:48:47.243936Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:47.243939Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "byteNonConst"::Merge::0
2023-01-27T07:48:47.243941Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/byteNonConst.json"
2023-01-27T07:48:47.243945Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:47.243949Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:47.244092Z  INFO evm_eth_compliance::statetest::runner: UC : "byteNonConst"
2023-01-27T07:48:47.244098Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1619056,
    events_root: None,
}
2023-01-27T07:48:47.246302Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:366.76642ms
2023-01-27T07:48:47.520954Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/callNonConst.json", Total Files :: 1
2023-01-27T07:48:47.587615Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:48:47.587758Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:47.587763Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:48:47.587820Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:47.587895Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:47.587899Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callNonConst"::Istanbul::0
2023-01-27T07:48:47.587902Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/callNonConst.json"
2023-01-27T07:48:47.587907Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:47.587909Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:47.948784Z  INFO evm_eth_compliance::statetest::runner: UC : "callNonConst"
2023-01-27T07:48:47.948798Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2807993,
    events_root: None,
}
2023-01-27T07:48:47.948809Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:47.948813Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callNonConst"::Istanbul::0
2023-01-27T07:48:47.948815Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/callNonConst.json"
2023-01-27T07:48:47.948818Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:47.948819Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:47.948977Z  INFO evm_eth_compliance::statetest::runner: UC : "callNonConst"
2023-01-27T07:48:47.948981Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1908214,
    events_root: None,
}
2023-01-27T07:48:47.948986Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:47.948989Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callNonConst"::Berlin::0
2023-01-27T07:48:47.948990Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/callNonConst.json"
2023-01-27T07:48:47.948993Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:47.948994Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:47.949116Z  INFO evm_eth_compliance::statetest::runner: UC : "callNonConst"
2023-01-27T07:48:47.949120Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1908214,
    events_root: None,
}
2023-01-27T07:48:47.949126Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:47.949128Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callNonConst"::Berlin::0
2023-01-27T07:48:47.949130Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/callNonConst.json"
2023-01-27T07:48:47.949133Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:47.949134Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:47.949255Z  INFO evm_eth_compliance::statetest::runner: UC : "callNonConst"
2023-01-27T07:48:47.949259Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1908214,
    events_root: None,
}
2023-01-27T07:48:47.949265Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:47.949266Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callNonConst"::London::0
2023-01-27T07:48:47.949268Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/callNonConst.json"
2023-01-27T07:48:47.949271Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:47.949272Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:47.949406Z  INFO evm_eth_compliance::statetest::runner: UC : "callNonConst"
2023-01-27T07:48:47.949410Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1908214,
    events_root: None,
}
2023-01-27T07:48:47.949416Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:47.949418Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callNonConst"::London::0
2023-01-27T07:48:47.949420Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/callNonConst.json"
2023-01-27T07:48:47.949422Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:47.949423Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:47.949545Z  INFO evm_eth_compliance::statetest::runner: UC : "callNonConst"
2023-01-27T07:48:47.949549Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1908214,
    events_root: None,
}
2023-01-27T07:48:47.949554Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:47.949556Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callNonConst"::Merge::0
2023-01-27T07:48:47.949558Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/callNonConst.json"
2023-01-27T07:48:47.949561Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:47.949562Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:47.949685Z  INFO evm_eth_compliance::statetest::runner: UC : "callNonConst"
2023-01-27T07:48:47.949689Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1908214,
    events_root: None,
}
2023-01-27T07:48:47.949696Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:47.949699Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callNonConst"::Merge::0
2023-01-27T07:48:47.949701Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/callNonConst.json"
2023-01-27T07:48:47.949704Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:47.949706Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:47.949866Z  INFO evm_eth_compliance::statetest::runner: UC : "callNonConst"
2023-01-27T07:48:47.949870Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1908214,
    events_root: None,
}
2023-01-27T07:48:47.951465Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:362.264574ms
2023-01-27T07:48:48.235112Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/callcodeNonConst.json", Total Files :: 1
2023-01-27T07:48:48.300590Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:48:48.300728Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:48.300732Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:48:48.300786Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:48.300859Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:48.300862Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeNonConst"::Istanbul::0
2023-01-27T07:48:48.300865Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/callcodeNonConst.json"
2023-01-27T07:48:48.300868Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:48.300869Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:48.663424Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeNonConst"
2023-01-27T07:48:48.663439Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1854846,
    events_root: None,
}
2023-01-27T07:48:48.663446Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=154): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T07:48:48.663461Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:48.663465Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeNonConst"::Istanbul::0
2023-01-27T07:48:48.663467Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/callcodeNonConst.json"
2023-01-27T07:48:48.663470Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:48.663471Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:48.663601Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeNonConst"
2023-01-27T07:48:48.663605Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1854846,
    events_root: None,
}
2023-01-27T07:48:48.663608Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=154): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T07:48:48.663617Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:48.663619Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeNonConst"::Berlin::0
2023-01-27T07:48:48.663621Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/callcodeNonConst.json"
2023-01-27T07:48:48.663624Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:48.663625Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:48.663737Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeNonConst"
2023-01-27T07:48:48.663740Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1854846,
    events_root: None,
}
2023-01-27T07:48:48.663743Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=154): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T07:48:48.663753Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:48.663755Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeNonConst"::Berlin::0
2023-01-27T07:48:48.663756Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/callcodeNonConst.json"
2023-01-27T07:48:48.663759Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:48.663760Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:48.663868Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeNonConst"
2023-01-27T07:48:48.663872Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1854846,
    events_root: None,
}
2023-01-27T07:48:48.663875Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=154): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T07:48:48.663887Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:48.663889Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeNonConst"::London::0
2023-01-27T07:48:48.663892Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/callcodeNonConst.json"
2023-01-27T07:48:48.663896Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:48.663898Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:48.664030Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeNonConst"
2023-01-27T07:48:48.664034Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1854846,
    events_root: None,
}
2023-01-27T07:48:48.664036Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=154): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T07:48:48.664046Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:48.664048Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeNonConst"::London::0
2023-01-27T07:48:48.664049Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/callcodeNonConst.json"
2023-01-27T07:48:48.664052Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:48.664053Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:48.664162Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeNonConst"
2023-01-27T07:48:48.664166Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1854846,
    events_root: None,
}
2023-01-27T07:48:48.664169Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=154): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T07:48:48.664178Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:48.664180Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeNonConst"::Merge::0
2023-01-27T07:48:48.664182Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/callcodeNonConst.json"
2023-01-27T07:48:48.664184Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:48.664185Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:48.664293Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeNonConst"
2023-01-27T07:48:48.664297Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1854846,
    events_root: None,
}
2023-01-27T07:48:48.664300Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=154): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T07:48:48.664308Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:48.664310Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeNonConst"::Merge::0
2023-01-27T07:48:48.664312Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/callcodeNonConst.json"
2023-01-27T07:48:48.664314Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:48.664316Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:48.664422Z  INFO evm_eth_compliance::statetest::runner: UC : "callcodeNonConst"
2023-01-27T07:48:48.664426Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1854846,
    events_root: None,
}
2023-01-27T07:48:48.664429Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=154): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T07:48:48.666184Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:363.852364ms
2023-01-27T07:48:48.947911Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/calldatacopyNonConst.json", Total Files :: 1
2023-01-27T07:48:49.003875Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:48:49.004050Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:49.004055Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:48:49.004122Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:49.004212Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:49.004215Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopyNonConst"::Istanbul::0
2023-01-27T07:48:49.004218Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/calldatacopyNonConst.json"
2023-01-27T07:48:49.004221Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:49.004223Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:49.410114Z  INFO evm_eth_compliance::statetest::runner: UC : "calldatacopyNonConst"
2023-01-27T07:48:49.410130Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1661696,
    events_root: None,
}
2023-01-27T07:48:49.410141Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-27T07:48:49.410145Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopyNonConst"::Istanbul::1
2023-01-27T07:48:49.410148Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/calldatacopyNonConst.json"
2023-01-27T07:48:49.410151Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-27T07:48:49.410152Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:49.410282Z  INFO evm_eth_compliance::statetest::runner: UC : "calldatacopyNonConst"
2023-01-27T07:48:49.410286Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1658437,
    events_root: None,
}
2023-01-27T07:48:49.410292Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:49.410293Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopyNonConst"::Istanbul::0
2023-01-27T07:48:49.410296Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/calldatacopyNonConst.json"
2023-01-27T07:48:49.410298Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:49.410301Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:49.410401Z  INFO evm_eth_compliance::statetest::runner: UC : "calldatacopyNonConst"
2023-01-27T07:48:49.410405Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1661696,
    events_root: None,
}
2023-01-27T07:48:49.410411Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-27T07:48:49.410413Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopyNonConst"::Istanbul::1
2023-01-27T07:48:49.410415Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/calldatacopyNonConst.json"
2023-01-27T07:48:49.410417Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-27T07:48:49.410419Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:49.410516Z  INFO evm_eth_compliance::statetest::runner: UC : "calldatacopyNonConst"
2023-01-27T07:48:49.410520Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1658437,
    events_root: None,
}
2023-01-27T07:48:49.410526Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:49.410528Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopyNonConst"::Berlin::0
2023-01-27T07:48:49.410529Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/calldatacopyNonConst.json"
2023-01-27T07:48:49.410532Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:49.410533Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:49.410634Z  INFO evm_eth_compliance::statetest::runner: UC : "calldatacopyNonConst"
2023-01-27T07:48:49.410639Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1661696,
    events_root: None,
}
2023-01-27T07:48:49.410645Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-27T07:48:49.410647Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopyNonConst"::Berlin::1
2023-01-27T07:48:49.410649Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/calldatacopyNonConst.json"
2023-01-27T07:48:49.410651Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-27T07:48:49.410653Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:49.410749Z  INFO evm_eth_compliance::statetest::runner: UC : "calldatacopyNonConst"
2023-01-27T07:48:49.410753Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1658437,
    events_root: None,
}
2023-01-27T07:48:49.410760Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:49.410762Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopyNonConst"::Berlin::0
2023-01-27T07:48:49.410764Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/calldatacopyNonConst.json"
2023-01-27T07:48:49.410767Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:49.410769Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:49.410865Z  INFO evm_eth_compliance::statetest::runner: UC : "calldatacopyNonConst"
2023-01-27T07:48:49.410869Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1661696,
    events_root: None,
}
2023-01-27T07:48:49.410874Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-27T07:48:49.410877Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopyNonConst"::Berlin::1
2023-01-27T07:48:49.410878Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/calldatacopyNonConst.json"
2023-01-27T07:48:49.410882Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-27T07:48:49.410883Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:49.410981Z  INFO evm_eth_compliance::statetest::runner: UC : "calldatacopyNonConst"
2023-01-27T07:48:49.410985Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1658437,
    events_root: None,
}
2023-01-27T07:48:49.410990Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:49.410993Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopyNonConst"::London::0
2023-01-27T07:48:49.410994Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/calldatacopyNonConst.json"
2023-01-27T07:48:49.410997Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:49.410998Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:49.411095Z  INFO evm_eth_compliance::statetest::runner: UC : "calldatacopyNonConst"
2023-01-27T07:48:49.411099Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1661696,
    events_root: None,
}
2023-01-27T07:48:49.411105Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-27T07:48:49.411107Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopyNonConst"::London::1
2023-01-27T07:48:49.411109Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/calldatacopyNonConst.json"
2023-01-27T07:48:49.411111Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-27T07:48:49.411113Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:49.411216Z  INFO evm_eth_compliance::statetest::runner: UC : "calldatacopyNonConst"
2023-01-27T07:48:49.411220Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1658437,
    events_root: None,
}
2023-01-27T07:48:49.411225Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:49.411227Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopyNonConst"::London::0
2023-01-27T07:48:49.411229Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/calldatacopyNonConst.json"
2023-01-27T07:48:49.411232Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:49.411233Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:49.411330Z  INFO evm_eth_compliance::statetest::runner: UC : "calldatacopyNonConst"
2023-01-27T07:48:49.411334Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1661696,
    events_root: None,
}
2023-01-27T07:48:49.411338Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-27T07:48:49.411341Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopyNonConst"::London::1
2023-01-27T07:48:49.411343Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/calldatacopyNonConst.json"
2023-01-27T07:48:49.411345Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-27T07:48:49.411347Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:49.411443Z  INFO evm_eth_compliance::statetest::runner: UC : "calldatacopyNonConst"
2023-01-27T07:48:49.411447Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1658437,
    events_root: None,
}
2023-01-27T07:48:49.411452Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:49.411454Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopyNonConst"::Merge::0
2023-01-27T07:48:49.411456Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/calldatacopyNonConst.json"
2023-01-27T07:48:49.411459Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:49.411460Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:49.411559Z  INFO evm_eth_compliance::statetest::runner: UC : "calldatacopyNonConst"
2023-01-27T07:48:49.411564Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1661696,
    events_root: None,
}
2023-01-27T07:48:49.411571Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-27T07:48:49.411573Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopyNonConst"::Merge::1
2023-01-27T07:48:49.411575Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/calldatacopyNonConst.json"
2023-01-27T07:48:49.411578Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-27T07:48:49.411579Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:49.411675Z  INFO evm_eth_compliance::statetest::runner: UC : "calldatacopyNonConst"
2023-01-27T07:48:49.411679Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1658437,
    events_root: None,
}
2023-01-27T07:48:49.411685Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:49.411688Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopyNonConst"::Merge::0
2023-01-27T07:48:49.411691Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/calldatacopyNonConst.json"
2023-01-27T07:48:49.411694Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:49.411696Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:49.411797Z  INFO evm_eth_compliance::statetest::runner: UC : "calldatacopyNonConst"
2023-01-27T07:48:49.411801Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1661696,
    events_root: None,
}
2023-01-27T07:48:49.411807Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-27T07:48:49.411809Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldatacopyNonConst"::Merge::1
2023-01-27T07:48:49.411811Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/calldatacopyNonConst.json"
2023-01-27T07:48:49.411814Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-27T07:48:49.411816Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:49.411911Z  INFO evm_eth_compliance::statetest::runner: UC : "calldatacopyNonConst"
2023-01-27T07:48:49.411915Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1658437,
    events_root: None,
}
2023-01-27T07:48:49.413553Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:408.051348ms
2023-01-27T07:48:49.678312Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/calldataloadNonConst.json", Total Files :: 1
2023-01-27T07:48:49.732564Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:48:49.732697Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:49.732701Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:48:49.732753Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:49.732822Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-27T07:48:49.732825Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldataloadNonConst"::Istanbul::1
2023-01-27T07:48:49.732828Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/calldataloadNonConst.json"
2023-01-27T07:48:49.732831Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-27T07:48:49.732833Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:50.081784Z  INFO evm_eth_compliance::statetest::runner: UC : "calldataloadNonConst"
2023-01-27T07:48:50.081808Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2544295,
    events_root: None,
}
2023-01-27T07:48:50.081822Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:50.081827Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldataloadNonConst"::Istanbul::0
2023-01-27T07:48:50.081829Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/calldataloadNonConst.json"
2023-01-27T07:48:50.081833Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:50.081835Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:50.082011Z  INFO evm_eth_compliance::statetest::runner: UC : "calldataloadNonConst"
2023-01-27T07:48:50.082016Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2494903,
    events_root: None,
}
2023-01-27T07:48:50.082022Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-27T07:48:50.082024Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldataloadNonConst"::Istanbul::1
2023-01-27T07:48:50.082027Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/calldataloadNonConst.json"
2023-01-27T07:48:50.082032Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-27T07:48:50.082033Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:50.082142Z  INFO evm_eth_compliance::statetest::runner: UC : "calldataloadNonConst"
2023-01-27T07:48:50.082147Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2544295,
    events_root: None,
}
2023-01-27T07:48:50.082152Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:50.082154Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldataloadNonConst"::Istanbul::0
2023-01-27T07:48:50.082156Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/calldataloadNonConst.json"
2023-01-27T07:48:50.082158Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:50.082160Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:50.082262Z  INFO evm_eth_compliance::statetest::runner: UC : "calldataloadNonConst"
2023-01-27T07:48:50.082266Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2494903,
    events_root: None,
}
2023-01-27T07:48:50.082271Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-27T07:48:50.082273Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldataloadNonConst"::Berlin::1
2023-01-27T07:48:50.082274Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/calldataloadNonConst.json"
2023-01-27T07:48:50.082277Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-27T07:48:50.082278Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:50.082380Z  INFO evm_eth_compliance::statetest::runner: UC : "calldataloadNonConst"
2023-01-27T07:48:50.082384Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2544295,
    events_root: None,
}
2023-01-27T07:48:50.082389Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:50.082391Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldataloadNonConst"::Berlin::0
2023-01-27T07:48:50.082393Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/calldataloadNonConst.json"
2023-01-27T07:48:50.082395Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:50.082397Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:50.082512Z  INFO evm_eth_compliance::statetest::runner: UC : "calldataloadNonConst"
2023-01-27T07:48:50.082516Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2494903,
    events_root: None,
}
2023-01-27T07:48:50.082522Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-27T07:48:50.082524Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldataloadNonConst"::Berlin::1
2023-01-27T07:48:50.082525Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/calldataloadNonConst.json"
2023-01-27T07:48:50.082528Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-27T07:48:50.082529Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:50.082632Z  INFO evm_eth_compliance::statetest::runner: UC : "calldataloadNonConst"
2023-01-27T07:48:50.082636Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2544295,
    events_root: None,
}
2023-01-27T07:48:50.082641Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:50.082643Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldataloadNonConst"::Berlin::0
2023-01-27T07:48:50.082645Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/calldataloadNonConst.json"
2023-01-27T07:48:50.082648Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:50.082649Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:50.082749Z  INFO evm_eth_compliance::statetest::runner: UC : "calldataloadNonConst"
2023-01-27T07:48:50.082753Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2494903,
    events_root: None,
}
2023-01-27T07:48:50.082758Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-27T07:48:50.082760Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldataloadNonConst"::London::1
2023-01-27T07:48:50.082761Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/calldataloadNonConst.json"
2023-01-27T07:48:50.082764Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-27T07:48:50.082765Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:50.082865Z  INFO evm_eth_compliance::statetest::runner: UC : "calldataloadNonConst"
2023-01-27T07:48:50.082869Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2544295,
    events_root: None,
}
2023-01-27T07:48:50.082874Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:50.082875Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldataloadNonConst"::London::0
2023-01-27T07:48:50.082877Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/calldataloadNonConst.json"
2023-01-27T07:48:50.082880Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:50.082881Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:50.082982Z  INFO evm_eth_compliance::statetest::runner: UC : "calldataloadNonConst"
2023-01-27T07:48:50.082986Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2494903,
    events_root: None,
}
2023-01-27T07:48:50.082991Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-27T07:48:50.082993Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldataloadNonConst"::London::1
2023-01-27T07:48:50.082994Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/calldataloadNonConst.json"
2023-01-27T07:48:50.082997Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-27T07:48:50.082998Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:50.083097Z  INFO evm_eth_compliance::statetest::runner: UC : "calldataloadNonConst"
2023-01-27T07:48:50.083102Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2544295,
    events_root: None,
}
2023-01-27T07:48:50.083107Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:50.083108Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldataloadNonConst"::London::0
2023-01-27T07:48:50.083110Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/calldataloadNonConst.json"
2023-01-27T07:48:50.083113Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:50.083114Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:50.083217Z  INFO evm_eth_compliance::statetest::runner: UC : "calldataloadNonConst"
2023-01-27T07:48:50.083221Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2494903,
    events_root: None,
}
2023-01-27T07:48:50.083226Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-27T07:48:50.083228Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldataloadNonConst"::Merge::1
2023-01-27T07:48:50.083229Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/calldataloadNonConst.json"
2023-01-27T07:48:50.083232Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-27T07:48:50.083233Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:50.083335Z  INFO evm_eth_compliance::statetest::runner: UC : "calldataloadNonConst"
2023-01-27T07:48:50.083339Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2544295,
    events_root: None,
}
2023-01-27T07:48:50.083344Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:50.083347Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldataloadNonConst"::Merge::0
2023-01-27T07:48:50.083348Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/calldataloadNonConst.json"
2023-01-27T07:48:50.083351Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:50.083352Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:50.083454Z  INFO evm_eth_compliance::statetest::runner: UC : "calldataloadNonConst"
2023-01-27T07:48:50.083458Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2494903,
    events_root: None,
}
2023-01-27T07:48:50.083464Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-27T07:48:50.083466Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldataloadNonConst"::Merge::1
2023-01-27T07:48:50.083468Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/calldataloadNonConst.json"
2023-01-27T07:48:50.083470Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-27T07:48:50.083472Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:50.083573Z  INFO evm_eth_compliance::statetest::runner: UC : "calldataloadNonConst"
2023-01-27T07:48:50.083577Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2544295,
    events_root: None,
}
2023-01-27T07:48:50.083583Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:50.083585Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "calldataloadNonConst"::Merge::0
2023-01-27T07:48:50.083587Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/calldataloadNonConst.json"
2023-01-27T07:48:50.083589Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:50.083591Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:50.083693Z  INFO evm_eth_compliance::statetest::runner: UC : "calldataloadNonConst"
2023-01-27T07:48:50.083697Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2494903,
    events_root: None,
}
2023-01-27T07:48:50.085576Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:351.14378ms
2023-01-27T07:48:50.372633Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/codecopyNonConst.json", Total Files :: 1
2023-01-27T07:48:50.412603Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:48:50.412740Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:50.412744Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:48:50.412801Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:50.412874Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:50.412877Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "codecopyNonConst"::Istanbul::0
2023-01-27T07:48:50.412880Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/codecopyNonConst.json"
2023-01-27T07:48:50.412883Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:50.412885Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:50.813121Z  INFO evm_eth_compliance::statetest::runner: UC : "codecopyNonConst"
2023-01-27T07:48:50.813136Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1661720,
    events_root: None,
}
2023-01-27T07:48:50.813148Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:50.813152Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "codecopyNonConst"::Istanbul::0
2023-01-27T07:48:50.813154Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/codecopyNonConst.json"
2023-01-27T07:48:50.813157Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:50.813159Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:50.813341Z  INFO evm_eth_compliance::statetest::runner: UC : "codecopyNonConst"
2023-01-27T07:48:50.813361Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1661720,
    events_root: None,
}
2023-01-27T07:48:50.813369Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:50.813371Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "codecopyNonConst"::Berlin::0
2023-01-27T07:48:50.813373Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/codecopyNonConst.json"
2023-01-27T07:48:50.813376Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:50.813379Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:50.813505Z  INFO evm_eth_compliance::statetest::runner: UC : "codecopyNonConst"
2023-01-27T07:48:50.813512Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1661720,
    events_root: None,
}
2023-01-27T07:48:50.813519Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:50.813521Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "codecopyNonConst"::Berlin::0
2023-01-27T07:48:50.813524Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/codecopyNonConst.json"
2023-01-27T07:48:50.813527Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:50.813529Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:50.813650Z  INFO evm_eth_compliance::statetest::runner: UC : "codecopyNonConst"
2023-01-27T07:48:50.813655Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1661720,
    events_root: None,
}
2023-01-27T07:48:50.813662Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:50.813664Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "codecopyNonConst"::London::0
2023-01-27T07:48:50.813667Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/codecopyNonConst.json"
2023-01-27T07:48:50.813670Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:50.813672Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:50.813781Z  INFO evm_eth_compliance::statetest::runner: UC : "codecopyNonConst"
2023-01-27T07:48:50.813785Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1661720,
    events_root: None,
}
2023-01-27T07:48:50.813790Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:50.813793Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "codecopyNonConst"::London::0
2023-01-27T07:48:50.813794Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/codecopyNonConst.json"
2023-01-27T07:48:50.813797Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:50.813798Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:50.813893Z  INFO evm_eth_compliance::statetest::runner: UC : "codecopyNonConst"
2023-01-27T07:48:50.813896Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1661720,
    events_root: None,
}
2023-01-27T07:48:50.813902Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:50.813904Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "codecopyNonConst"::Merge::0
2023-01-27T07:48:50.813905Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/codecopyNonConst.json"
2023-01-27T07:48:50.813908Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:50.813909Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:50.814025Z  INFO evm_eth_compliance::statetest::runner: UC : "codecopyNonConst"
2023-01-27T07:48:50.814030Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1661720,
    events_root: None,
}
2023-01-27T07:48:50.814037Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:50.814040Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "codecopyNonConst"::Merge::0
2023-01-27T07:48:50.814042Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/codecopyNonConst.json"
2023-01-27T07:48:50.814045Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:50.814047Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:50.814169Z  INFO evm_eth_compliance::statetest::runner: UC : "codecopyNonConst"
2023-01-27T07:48:50.814174Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1661720,
    events_root: None,
}
2023-01-27T07:48:50.816207Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:401.584013ms
2023-01-27T07:48:51.110442Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/createNonConst.json", Total Files :: 1
2023-01-27T07:48:51.167021Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:48:51.167157Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:51.167160Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:48:51.167216Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:51.167286Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:51.167289Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNonConst"::Istanbul::0
2023-01-27T07:48:51.167292Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/createNonConst.json"
2023-01-27T07:48:51.167295Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:51.167297Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-27T07:48:51.821600Z  INFO evm_eth_compliance::statetest::runner: UC : "createNonConst"
2023-01-27T07:48:51.821610Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14604431,
    events_root: None,
}
2023-01-27T07:48:51.821636Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:51.821640Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNonConst"::Istanbul::0
2023-01-27T07:48:51.821642Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/createNonConst.json"
2023-01-27T07:48:51.821645Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:51.821646Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [184, 141, 232, 139, 53, 236, 191, 60, 20, 30, 60, 170, 226, 186, 243, 88, 52, 209, 143, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-01-27T07:48:51.822270Z  INFO evm_eth_compliance::statetest::runner: UC : "createNonConst"
2023-01-27T07:48:51.822275Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13532568,
    events_root: None,
}
2023-01-27T07:48:51.822293Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:51.822295Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNonConst"::Berlin::0
2023-01-27T07:48:51.822297Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/createNonConst.json"
2023-01-27T07:48:51.822299Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:51.822301Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [93, 53, 72, 12, 110, 127, 137, 82, 54, 63, 162, 128, 160, 169, 105, 6, 218, 152, 31, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-01-27T07:48:51.822856Z  INFO evm_eth_compliance::statetest::runner: UC : "createNonConst"
2023-01-27T07:48:51.822861Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14450967,
    events_root: None,
}
2023-01-27T07:48:51.822877Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:51.822880Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNonConst"::Berlin::0
2023-01-27T07:48:51.822881Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/createNonConst.json"
2023-01-27T07:48:51.822884Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:51.822885Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [91, 91, 211, 67, 161, 47, 180, 44, 98, 57, 10, 255, 99, 64, 181, 153, 71, 182, 2, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-01-27T07:48:51.823471Z  INFO evm_eth_compliance::statetest::runner: UC : "createNonConst"
2023-01-27T07:48:51.823476Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14968739,
    events_root: None,
}
2023-01-27T07:48:51.823493Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:51.823495Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNonConst"::London::0
2023-01-27T07:48:51.823497Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/createNonConst.json"
2023-01-27T07:48:51.823500Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:51.823502Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [162, 185, 31, 213, 149, 197, 29, 236, 63, 228, 43, 225, 251, 243, 191, 203, 59, 201, 228, 237, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([236, 70, 216, 243, 101, 99, 189, 62, 205, 26, 208, 253, 84, 36, 48, 143, 166, 88, 135, 41]) }
2023-01-27T07:48:51.824051Z  INFO evm_eth_compliance::statetest::runner: UC : "createNonConst"
2023-01-27T07:48:51.824056Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14236591,
    events_root: None,
}
2023-01-27T07:48:51.824073Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:51.824076Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNonConst"::London::0
2023-01-27T07:48:51.824078Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/createNonConst.json"
2023-01-27T07:48:51.824081Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:51.824083Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [231, 145, 128, 153, 167, 205, 154, 106, 229, 214, 94, 169, 200, 101, 174, 16, 75, 17, 103, 40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([155, 99, 140, 31, 46, 96, 27, 93, 44, 60, 131, 66, 80, 136, 87, 209, 224, 27, 216, 212]) }
2023-01-27T07:48:51.824711Z  INFO evm_eth_compliance::statetest::runner: UC : "createNonConst"
2023-01-27T07:48:51.824716Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14879025,
    events_root: None,
}
2023-01-27T07:48:51.824733Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:51.824735Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNonConst"::Merge::0
2023-01-27T07:48:51.824737Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/createNonConst.json"
2023-01-27T07:48:51.824740Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:51.824741Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [145, 154, 155, 228, 108, 215, 118, 152, 145, 199, 117, 238, 186, 223, 131, 66, 46, 94, 228, 43, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([188, 149, 186, 245, 1, 91, 222, 203, 63, 25, 86, 169, 35, 110, 18, 124, 122, 60, 238, 128]) }
2023-01-27T07:48:51.825292Z  INFO evm_eth_compliance::statetest::runner: UC : "createNonConst"
2023-01-27T07:48:51.825297Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14412445,
    events_root: None,
}
2023-01-27T07:48:51.825314Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:51.825320Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNonConst"::Merge::0
2023-01-27T07:48:51.825323Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/createNonConst.json"
2023-01-27T07:48:51.825326Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:51.825328Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [51, 109, 112, 15, 18, 162, 2, 183, 68, 107, 0, 247, 107, 74, 12, 94, 226, 21, 112, 50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([20, 3, 204, 71, 166, 252, 88, 221, 29, 77, 14, 224, 191, 132, 61, 100, 47, 53, 166, 175]) }
2023-01-27T07:48:51.825903Z  INFO evm_eth_compliance::statetest::runner: UC : "createNonConst"
2023-01-27T07:48:51.825908Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14538491,
    events_root: None,
}
2023-01-27T07:48:51.827527Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:658.909613ms
2023-01-27T07:48:52.108946Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/delegatecallNonConst.json", Total Files :: 1
2023-01-27T07:48:52.139635Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:48:52.139776Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:52.139779Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:48:52.139833Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:52.139909Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:52.139912Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallNonConst"::Istanbul::0
2023-01-27T07:48:52.139915Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/delegatecallNonConst.json"
2023-01-27T07:48:52.139918Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:52.139920Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:52.555544Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallNonConst"
2023-01-27T07:48:52.555560Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2764257,
    events_root: None,
}
2023-01-27T07:48:52.555573Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:52.555577Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallNonConst"::Istanbul::0
2023-01-27T07:48:52.555579Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/delegatecallNonConst.json"
2023-01-27T07:48:52.555582Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:52.555583Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:52.555728Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallNonConst"
2023-01-27T07:48:52.555732Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1864478,
    events_root: None,
}
2023-01-27T07:48:52.555738Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:52.555741Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallNonConst"::Berlin::0
2023-01-27T07:48:52.555743Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/delegatecallNonConst.json"
2023-01-27T07:48:52.555746Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:52.555747Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:52.555873Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallNonConst"
2023-01-27T07:48:52.555878Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1864478,
    events_root: None,
}
2023-01-27T07:48:52.555884Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:52.555886Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallNonConst"::Berlin::0
2023-01-27T07:48:52.555888Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/delegatecallNonConst.json"
2023-01-27T07:48:52.555891Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:52.555892Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:52.556016Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallNonConst"
2023-01-27T07:48:52.556020Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1864478,
    events_root: None,
}
2023-01-27T07:48:52.556025Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:52.556027Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallNonConst"::London::0
2023-01-27T07:48:52.556029Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/delegatecallNonConst.json"
2023-01-27T07:48:52.556032Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:52.556033Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:52.556157Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallNonConst"
2023-01-27T07:48:52.556161Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1864478,
    events_root: None,
}
2023-01-27T07:48:52.556166Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:52.556168Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallNonConst"::London::0
2023-01-27T07:48:52.556171Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/delegatecallNonConst.json"
2023-01-27T07:48:52.556174Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:52.556175Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:52.556297Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallNonConst"
2023-01-27T07:48:52.556301Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1864478,
    events_root: None,
}
2023-01-27T07:48:52.556308Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:52.556310Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallNonConst"::Merge::0
2023-01-27T07:48:52.556312Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/delegatecallNonConst.json"
2023-01-27T07:48:52.556314Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:52.556316Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:52.556440Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallNonConst"
2023-01-27T07:48:52.556444Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1864478,
    events_root: None,
}
2023-01-27T07:48:52.556450Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:52.556452Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "delegatecallNonConst"::Merge::0
2023-01-27T07:48:52.556453Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/delegatecallNonConst.json"
2023-01-27T07:48:52.556456Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:52.556457Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:52.556581Z  INFO evm_eth_compliance::statetest::runner: UC : "delegatecallNonConst"
2023-01-27T07:48:52.556585Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1864478,
    events_root: None,
}
2023-01-27T07:48:52.558428Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:416.960407ms
2023-01-27T07:48:52.821344Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/divNonConst.json", Total Files :: 1
2023-01-27T07:48:52.868127Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:48:52.868268Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:52.868272Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:48:52.868326Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:52.868398Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:52.868401Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divNonConst"::Istanbul::0
2023-01-27T07:48:52.868404Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/divNonConst.json"
2023-01-27T07:48:52.868406Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:52.868408Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:53.215402Z  INFO evm_eth_compliance::statetest::runner: UC : "divNonConst"
2023-01-27T07:48:53.215419Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618752,
    events_root: None,
}
2023-01-27T07:48:53.215430Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:53.215434Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divNonConst"::Istanbul::0
2023-01-27T07:48:53.215436Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/divNonConst.json"
2023-01-27T07:48:53.215439Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:53.215440Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:53.215574Z  INFO evm_eth_compliance::statetest::runner: UC : "divNonConst"
2023-01-27T07:48:53.215579Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618752,
    events_root: None,
}
2023-01-27T07:48:53.215586Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:53.215589Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divNonConst"::Berlin::0
2023-01-27T07:48:53.215591Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/divNonConst.json"
2023-01-27T07:48:53.215594Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:53.215596Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:53.215710Z  INFO evm_eth_compliance::statetest::runner: UC : "divNonConst"
2023-01-27T07:48:53.215715Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618752,
    events_root: None,
}
2023-01-27T07:48:53.215720Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:53.215723Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divNonConst"::Berlin::0
2023-01-27T07:48:53.215724Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/divNonConst.json"
2023-01-27T07:48:53.215727Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:53.215728Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:53.215826Z  INFO evm_eth_compliance::statetest::runner: UC : "divNonConst"
2023-01-27T07:48:53.215830Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618752,
    events_root: None,
}
2023-01-27T07:48:53.215835Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:53.215837Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divNonConst"::London::0
2023-01-27T07:48:53.215838Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/divNonConst.json"
2023-01-27T07:48:53.215841Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:53.215842Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:53.215933Z  INFO evm_eth_compliance::statetest::runner: UC : "divNonConst"
2023-01-27T07:48:53.215937Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618752,
    events_root: None,
}
2023-01-27T07:48:53.215942Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:53.215944Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divNonConst"::London::0
2023-01-27T07:48:53.215946Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/divNonConst.json"
2023-01-27T07:48:53.215948Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:53.215950Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:53.216039Z  INFO evm_eth_compliance::statetest::runner: UC : "divNonConst"
2023-01-27T07:48:53.216042Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618752,
    events_root: None,
}
2023-01-27T07:48:53.216048Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:53.216050Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divNonConst"::Merge::0
2023-01-27T07:48:53.216051Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/divNonConst.json"
2023-01-27T07:48:53.216054Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:53.216055Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:53.216144Z  INFO evm_eth_compliance::statetest::runner: UC : "divNonConst"
2023-01-27T07:48:53.216148Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618752,
    events_root: None,
}
2023-01-27T07:48:53.216153Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:53.216155Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "divNonConst"::Merge::0
2023-01-27T07:48:53.216157Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/divNonConst.json"
2023-01-27T07:48:53.216159Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:53.216160Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:53.216249Z  INFO evm_eth_compliance::statetest::runner: UC : "divNonConst"
2023-01-27T07:48:53.216255Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618752,
    events_root: None,
}
2023-01-27T07:48:53.217860Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:348.137986ms
2023-01-27T07:48:53.499466Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/eqNonConst.json", Total Files :: 1
2023-01-27T07:48:53.554164Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:48:53.554308Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:53.554311Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:48:53.554372Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:53.554444Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:53.554447Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "eqNonConst"::Istanbul::0
2023-01-27T07:48:53.554449Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/eqNonConst.json"
2023-01-27T07:48:53.554453Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:53.554454Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:53.930205Z  INFO evm_eth_compliance::statetest::runner: UC : "eqNonConst"
2023-01-27T07:48:53.930222Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2550895,
    events_root: None,
}
2023-01-27T07:48:53.930234Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:53.930238Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "eqNonConst"::Istanbul::0
2023-01-27T07:48:53.930239Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/eqNonConst.json"
2023-01-27T07:48:53.930242Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:53.930243Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:53.930386Z  INFO evm_eth_compliance::statetest::runner: UC : "eqNonConst"
2023-01-27T07:48:53.930390Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1651116,
    events_root: None,
}
2023-01-27T07:48:53.930396Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:53.930398Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "eqNonConst"::Berlin::0
2023-01-27T07:48:53.930399Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/eqNonConst.json"
2023-01-27T07:48:53.930402Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:53.930403Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:53.930505Z  INFO evm_eth_compliance::statetest::runner: UC : "eqNonConst"
2023-01-27T07:48:53.930509Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1651116,
    events_root: None,
}
2023-01-27T07:48:53.930514Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:53.930516Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "eqNonConst"::Berlin::0
2023-01-27T07:48:53.930518Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/eqNonConst.json"
2023-01-27T07:48:53.930520Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:53.930522Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:53.930622Z  INFO evm_eth_compliance::statetest::runner: UC : "eqNonConst"
2023-01-27T07:48:53.930626Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1651116,
    events_root: None,
}
2023-01-27T07:48:53.930631Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:53.930634Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "eqNonConst"::London::0
2023-01-27T07:48:53.930635Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/eqNonConst.json"
2023-01-27T07:48:53.930638Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:53.930639Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:53.930739Z  INFO evm_eth_compliance::statetest::runner: UC : "eqNonConst"
2023-01-27T07:48:53.930743Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1651116,
    events_root: None,
}
2023-01-27T07:48:53.930749Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:53.930750Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "eqNonConst"::London::0
2023-01-27T07:48:53.930752Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/eqNonConst.json"
2023-01-27T07:48:53.930754Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:53.930756Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:53.930853Z  INFO evm_eth_compliance::statetest::runner: UC : "eqNonConst"
2023-01-27T07:48:53.930858Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1651116,
    events_root: None,
}
2023-01-27T07:48:53.930863Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:53.930865Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "eqNonConst"::Merge::0
2023-01-27T07:48:53.930867Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/eqNonConst.json"
2023-01-27T07:48:53.930869Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:53.930871Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:53.930968Z  INFO evm_eth_compliance::statetest::runner: UC : "eqNonConst"
2023-01-27T07:48:53.930972Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1651116,
    events_root: None,
}
2023-01-27T07:48:53.930977Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:53.930980Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "eqNonConst"::Merge::0
2023-01-27T07:48:53.930982Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/eqNonConst.json"
2023-01-27T07:48:53.930985Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:53.930986Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:53.931127Z  INFO evm_eth_compliance::statetest::runner: UC : "eqNonConst"
2023-01-27T07:48:53.931134Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1651116,
    events_root: None,
}
2023-01-27T07:48:53.932878Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:376.981829ms
2023-01-27T07:48:54.224467Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/expNonConst.json", Total Files :: 1
2023-01-27T07:48:54.255848Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:48:54.255994Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:54.255997Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:48:54.256053Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:54.256150Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:54.256155Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "expNonConst"::Istanbul::0
2023-01-27T07:48:54.256159Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/expNonConst.json"
2023-01-27T07:48:54.256163Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:54.256166Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:54.633682Z  INFO evm_eth_compliance::statetest::runner: UC : "expNonConst"
2023-01-27T07:48:54.633695Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2548387,
    events_root: None,
}
2023-01-27T07:48:54.633706Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:54.633711Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "expNonConst"::Istanbul::0
2023-01-27T07:48:54.633712Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/expNonConst.json"
2023-01-27T07:48:54.633715Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:54.633717Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:54.633835Z  INFO evm_eth_compliance::statetest::runner: UC : "expNonConst"
2023-01-27T07:48:54.633839Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1648608,
    events_root: None,
}
2023-01-27T07:48:54.633845Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:54.633847Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "expNonConst"::Berlin::0
2023-01-27T07:48:54.633849Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/expNonConst.json"
2023-01-27T07:48:54.633851Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:54.633852Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:54.633945Z  INFO evm_eth_compliance::statetest::runner: UC : "expNonConst"
2023-01-27T07:48:54.633949Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1648608,
    events_root: None,
}
2023-01-27T07:48:54.633954Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:54.633956Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "expNonConst"::Berlin::0
2023-01-27T07:48:54.633958Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/expNonConst.json"
2023-01-27T07:48:54.633960Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:54.633961Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:54.634054Z  INFO evm_eth_compliance::statetest::runner: UC : "expNonConst"
2023-01-27T07:48:54.634058Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1648608,
    events_root: None,
}
2023-01-27T07:48:54.634063Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:54.634065Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "expNonConst"::London::0
2023-01-27T07:48:54.634067Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/expNonConst.json"
2023-01-27T07:48:54.634069Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:54.634071Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:54.634162Z  INFO evm_eth_compliance::statetest::runner: UC : "expNonConst"
2023-01-27T07:48:54.634166Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1648608,
    events_root: None,
}
2023-01-27T07:48:54.634171Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:54.634173Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "expNonConst"::London::0
2023-01-27T07:48:54.634174Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/expNonConst.json"
2023-01-27T07:48:54.634176Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:54.634178Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:54.634269Z  INFO evm_eth_compliance::statetest::runner: UC : "expNonConst"
2023-01-27T07:48:54.634273Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1648608,
    events_root: None,
}
2023-01-27T07:48:54.634278Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:54.634279Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "expNonConst"::Merge::0
2023-01-27T07:48:54.634281Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/expNonConst.json"
2023-01-27T07:48:54.634284Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:54.634285Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:54.634376Z  INFO evm_eth_compliance::statetest::runner: UC : "expNonConst"
2023-01-27T07:48:54.634380Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1648608,
    events_root: None,
}
2023-01-27T07:48:54.634385Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:54.634387Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "expNonConst"::Merge::0
2023-01-27T07:48:54.634389Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/expNonConst.json"
2023-01-27T07:48:54.634391Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:54.634393Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:54.634484Z  INFO evm_eth_compliance::statetest::runner: UC : "expNonConst"
2023-01-27T07:48:54.634488Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1648608,
    events_root: None,
}
2023-01-27T07:48:54.636036Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:378.64966ms
2023-01-27T07:48:54.935552Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/extcodecopyNonConst.json", Total Files :: 1
2023-01-27T07:48:54.993513Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:48:54.993652Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:54.993656Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:48:54.993713Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:54.993785Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:54.993788Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodecopyNonConst"::Istanbul::0
2023-01-27T07:48:54.993791Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/extcodecopyNonConst.json"
2023-01-27T07:48:54.993794Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:54.993795Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:55.370151Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodecopyNonConst"
2023-01-27T07:48:55.370167Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1735628,
    events_root: None,
}
2023-01-27T07:48:55.370177Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:55.370181Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodecopyNonConst"::Istanbul::0
2023-01-27T07:48:55.370183Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/extcodecopyNonConst.json"
2023-01-27T07:48:55.370186Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:55.370187Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:55.370335Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodecopyNonConst"
2023-01-27T07:48:55.370339Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1735628,
    events_root: None,
}
2023-01-27T07:48:55.370345Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:55.370347Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodecopyNonConst"::Berlin::0
2023-01-27T07:48:55.370349Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/extcodecopyNonConst.json"
2023-01-27T07:48:55.370351Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:55.370353Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:55.370462Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodecopyNonConst"
2023-01-27T07:48:55.370466Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1735628,
    events_root: None,
}
2023-01-27T07:48:55.370472Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:55.370474Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodecopyNonConst"::Berlin::0
2023-01-27T07:48:55.370475Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/extcodecopyNonConst.json"
2023-01-27T07:48:55.370478Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:55.370480Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:55.370624Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodecopyNonConst"
2023-01-27T07:48:55.370629Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1735628,
    events_root: None,
}
2023-01-27T07:48:55.370636Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:55.370639Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodecopyNonConst"::London::0
2023-01-27T07:48:55.370642Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/extcodecopyNonConst.json"
2023-01-27T07:48:55.370646Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:55.370648Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:55.370789Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodecopyNonConst"
2023-01-27T07:48:55.370794Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1735628,
    events_root: None,
}
2023-01-27T07:48:55.370799Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:55.370800Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodecopyNonConst"::London::0
2023-01-27T07:48:55.370802Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/extcodecopyNonConst.json"
2023-01-27T07:48:55.370805Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:55.370806Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:55.370921Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodecopyNonConst"
2023-01-27T07:48:55.370925Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1735628,
    events_root: None,
}
2023-01-27T07:48:55.370930Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:55.370932Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodecopyNonConst"::Merge::0
2023-01-27T07:48:55.370934Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/extcodecopyNonConst.json"
2023-01-27T07:48:55.370937Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:55.370938Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:55.371045Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodecopyNonConst"
2023-01-27T07:48:55.371049Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1735628,
    events_root: None,
}
2023-01-27T07:48:55.371054Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:55.371056Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodecopyNonConst"::Merge::0
2023-01-27T07:48:55.371058Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/extcodecopyNonConst.json"
2023-01-27T07:48:55.371061Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:55.371062Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:55.371169Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodecopyNonConst"
2023-01-27T07:48:55.371173Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1735628,
    events_root: None,
}
2023-01-27T07:48:55.372760Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:377.670422ms
2023-01-27T07:48:55.659291Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/extcodesizeNonConst.json", Total Files :: 1
2023-01-27T07:48:55.699404Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:48:55.699538Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:55.699541Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:48:55.699594Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:55.699665Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:55.699668Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodesizeNonConst"::Istanbul::0
2023-01-27T07:48:55.699671Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/extcodesizeNonConst.json"
2023-01-27T07:48:55.699675Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:55.699676Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:56.081631Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodesizeNonConst"
2023-01-27T07:48:56.081646Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1600802,
    events_root: None,
}
2023-01-27T07:48:56.081656Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:56.081661Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodesizeNonConst"::Istanbul::0
2023-01-27T07:48:56.081664Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/extcodesizeNonConst.json"
2023-01-27T07:48:56.081668Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:56.081670Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:56.081819Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodesizeNonConst"
2023-01-27T07:48:56.081824Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1600802,
    events_root: None,
}
2023-01-27T07:48:56.081831Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:56.081833Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodesizeNonConst"::Berlin::0
2023-01-27T07:48:56.081836Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/extcodesizeNonConst.json"
2023-01-27T07:48:56.081839Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:56.081841Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:56.081958Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodesizeNonConst"
2023-01-27T07:48:56.081963Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1600802,
    events_root: None,
}
2023-01-27T07:48:56.081969Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:56.081972Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodesizeNonConst"::Berlin::0
2023-01-27T07:48:56.081976Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/extcodesizeNonConst.json"
2023-01-27T07:48:56.081980Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:56.081981Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:56.082096Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodesizeNonConst"
2023-01-27T07:48:56.082104Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1600802,
    events_root: None,
}
2023-01-27T07:48:56.082110Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:56.082113Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodesizeNonConst"::London::0
2023-01-27T07:48:56.082116Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/extcodesizeNonConst.json"
2023-01-27T07:48:56.082119Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:56.082121Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:56.082235Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodesizeNonConst"
2023-01-27T07:48:56.082240Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1600802,
    events_root: None,
}
2023-01-27T07:48:56.082247Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:56.082250Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodesizeNonConst"::London::0
2023-01-27T07:48:56.082255Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/extcodesizeNonConst.json"
2023-01-27T07:48:56.082259Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:56.082261Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:56.082378Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodesizeNonConst"
2023-01-27T07:48:56.082382Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1600802,
    events_root: None,
}
2023-01-27T07:48:56.082388Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:56.082391Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodesizeNonConst"::Merge::0
2023-01-27T07:48:56.082394Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/extcodesizeNonConst.json"
2023-01-27T07:48:56.082397Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:56.082400Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:56.082515Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodesizeNonConst"
2023-01-27T07:48:56.082520Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1600802,
    events_root: None,
}
2023-01-27T07:48:56.082527Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:56.082530Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodesizeNonConst"::Merge::0
2023-01-27T07:48:56.082533Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/extcodesizeNonConst.json"
2023-01-27T07:48:56.082537Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:56.082538Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:56.082655Z  INFO evm_eth_compliance::statetest::runner: UC : "extcodesizeNonConst"
2023-01-27T07:48:56.082659Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1600802,
    events_root: None,
}
2023-01-27T07:48:56.084493Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:383.26632ms
2023-01-27T07:48:56.376163Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/gtNonConst.json", Total Files :: 1
2023-01-27T07:48:56.413957Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:48:56.414088Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:56.414092Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:48:56.414146Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:56.414218Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:56.414221Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "gtNonConst"::Istanbul::0
2023-01-27T07:48:56.414224Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/gtNonConst.json"
2023-01-27T07:48:56.414227Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:56.414228Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:56.793983Z  INFO evm_eth_compliance::statetest::runner: UC : "gtNonConst"
2023-01-27T07:48:56.793998Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618908,
    events_root: None,
}
2023-01-27T07:48:56.794009Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:56.794012Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "gtNonConst"::Istanbul::0
2023-01-27T07:48:56.794014Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/gtNonConst.json"
2023-01-27T07:48:56.794017Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:56.794018Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:56.794148Z  INFO evm_eth_compliance::statetest::runner: UC : "gtNonConst"
2023-01-27T07:48:56.794152Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618908,
    events_root: None,
}
2023-01-27T07:48:56.794157Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:56.794160Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "gtNonConst"::Berlin::0
2023-01-27T07:48:56.794162Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/gtNonConst.json"
2023-01-27T07:48:56.794164Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:56.794166Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:56.794255Z  INFO evm_eth_compliance::statetest::runner: UC : "gtNonConst"
2023-01-27T07:48:56.794259Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618908,
    events_root: None,
}
2023-01-27T07:48:56.794263Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:56.794266Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "gtNonConst"::Berlin::0
2023-01-27T07:48:56.794268Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/gtNonConst.json"
2023-01-27T07:48:56.794270Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:56.794271Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:56.794359Z  INFO evm_eth_compliance::statetest::runner: UC : "gtNonConst"
2023-01-27T07:48:56.794362Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618908,
    events_root: None,
}
2023-01-27T07:48:56.794367Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:56.794369Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "gtNonConst"::London::0
2023-01-27T07:48:56.794371Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/gtNonConst.json"
2023-01-27T07:48:56.794373Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:56.794375Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:56.794462Z  INFO evm_eth_compliance::statetest::runner: UC : "gtNonConst"
2023-01-27T07:48:56.794466Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618908,
    events_root: None,
}
2023-01-27T07:48:56.794470Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:56.794472Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "gtNonConst"::London::0
2023-01-27T07:48:56.794474Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/gtNonConst.json"
2023-01-27T07:48:56.794476Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:56.794478Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:56.794564Z  INFO evm_eth_compliance::statetest::runner: UC : "gtNonConst"
2023-01-27T07:48:56.794567Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618908,
    events_root: None,
}
2023-01-27T07:48:56.794572Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:56.794574Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "gtNonConst"::Merge::0
2023-01-27T07:48:56.794576Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/gtNonConst.json"
2023-01-27T07:48:56.794578Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:56.794579Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:56.794665Z  INFO evm_eth_compliance::statetest::runner: UC : "gtNonConst"
2023-01-27T07:48:56.794669Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618908,
    events_root: None,
}
2023-01-27T07:48:56.794673Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:56.794675Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "gtNonConst"::Merge::0
2023-01-27T07:48:56.794677Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/gtNonConst.json"
2023-01-27T07:48:56.794679Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:56.794680Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:56.794766Z  INFO evm_eth_compliance::statetest::runner: UC : "gtNonConst"
2023-01-27T07:48:56.794770Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618908,
    events_root: None,
}
2023-01-27T07:48:56.796154Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:380.823599ms
2023-01-27T07:48:57.059319Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/iszeroNonConst.json", Total Files :: 1
2023-01-27T07:48:57.099856Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:48:57.099995Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:57.099999Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:48:57.100053Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:57.100127Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:57.100130Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "iszeroNonConst"::Istanbul::0
2023-01-27T07:48:57.100132Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/iszeroNonConst.json"
2023-01-27T07:48:57.100136Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:57.100138Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:57.487617Z  INFO evm_eth_compliance::statetest::runner: UC : "iszeroNonConst"
2023-01-27T07:48:57.487635Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2501939,
    events_root: None,
}
2023-01-27T07:48:57.487647Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:57.487652Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "iszeroNonConst"::Istanbul::0
2023-01-27T07:48:57.487653Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/iszeroNonConst.json"
2023-01-27T07:48:57.487656Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:57.487658Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:57.487782Z  INFO evm_eth_compliance::statetest::runner: UC : "iszeroNonConst"
2023-01-27T07:48:57.487787Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1602161,
    events_root: None,
}
2023-01-27T07:48:57.487792Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:57.487794Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "iszeroNonConst"::Berlin::0
2023-01-27T07:48:57.487796Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/iszeroNonConst.json"
2023-01-27T07:48:57.487798Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:57.487800Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:57.487903Z  INFO evm_eth_compliance::statetest::runner: UC : "iszeroNonConst"
2023-01-27T07:48:57.487907Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1602161,
    events_root: None,
}
2023-01-27T07:48:57.487912Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:57.487914Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "iszeroNonConst"::Berlin::0
2023-01-27T07:48:57.487916Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/iszeroNonConst.json"
2023-01-27T07:48:57.487919Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:57.487921Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:57.488028Z  INFO evm_eth_compliance::statetest::runner: UC : "iszeroNonConst"
2023-01-27T07:48:57.488032Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1602161,
    events_root: None,
}
2023-01-27T07:48:57.488037Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:57.488039Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "iszeroNonConst"::London::0
2023-01-27T07:48:57.488041Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/iszeroNonConst.json"
2023-01-27T07:48:57.488043Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:57.488045Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:57.488144Z  INFO evm_eth_compliance::statetest::runner: UC : "iszeroNonConst"
2023-01-27T07:48:57.488148Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1602161,
    events_root: None,
}
2023-01-27T07:48:57.488153Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:57.488155Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "iszeroNonConst"::London::0
2023-01-27T07:48:57.488157Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/iszeroNonConst.json"
2023-01-27T07:48:57.488160Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:57.488162Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:57.488268Z  INFO evm_eth_compliance::statetest::runner: UC : "iszeroNonConst"
2023-01-27T07:48:57.488273Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1602161,
    events_root: None,
}
2023-01-27T07:48:57.488278Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:57.488280Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "iszeroNonConst"::Merge::0
2023-01-27T07:48:57.488282Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/iszeroNonConst.json"
2023-01-27T07:48:57.488285Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:57.488287Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:57.488403Z  INFO evm_eth_compliance::statetest::runner: UC : "iszeroNonConst"
2023-01-27T07:48:57.488408Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1602161,
    events_root: None,
}
2023-01-27T07:48:57.488413Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:57.488414Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "iszeroNonConst"::Merge::0
2023-01-27T07:48:57.488416Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/iszeroNonConst.json"
2023-01-27T07:48:57.488420Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:57.488421Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:57.488520Z  INFO evm_eth_compliance::statetest::runner: UC : "iszeroNonConst"
2023-01-27T07:48:57.488525Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1602161,
    events_root: None,
}
2023-01-27T07:48:57.490321Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:388.678295ms
2023-01-27T07:48:57.778178Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/jumpNonConst.json", Total Files :: 1
2023-01-27T07:48:57.833708Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:48:57.833845Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:57.833849Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:48:57.833903Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:57.833975Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:57.833978Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "jumpNonConst"::Istanbul::0
2023-01-27T07:48:57.833981Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/jumpNonConst.json"
2023-01-27T07:48:57.833984Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:57.833985Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:58.216323Z  INFO evm_eth_compliance::statetest::runner: UC : "jumpNonConst"
2023-01-27T07:48:58.216339Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1587383,
    events_root: None,
}
2023-01-27T07:48:58.216346Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=22): jumpdest 0 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T07:48:58.216359Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:58.216363Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "jumpNonConst"::Istanbul::0
2023-01-27T07:48:58.216365Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/jumpNonConst.json"
2023-01-27T07:48:58.216368Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:58.216370Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:58.216481Z  INFO evm_eth_compliance::statetest::runner: UC : "jumpNonConst"
2023-01-27T07:48:58.216486Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1587383,
    events_root: None,
}
2023-01-27T07:48:58.216489Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=22): jumpdest 0 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T07:48:58.216498Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:58.216500Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "jumpNonConst"::Berlin::0
2023-01-27T07:48:58.216502Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/jumpNonConst.json"
2023-01-27T07:48:58.216504Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:58.216505Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:58.216596Z  INFO evm_eth_compliance::statetest::runner: UC : "jumpNonConst"
2023-01-27T07:48:58.216600Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1587383,
    events_root: None,
}
2023-01-27T07:48:58.216603Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=22): jumpdest 0 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T07:48:58.216612Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:58.216614Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "jumpNonConst"::Berlin::0
2023-01-27T07:48:58.216616Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/jumpNonConst.json"
2023-01-27T07:48:58.216618Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:58.216619Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:58.216708Z  INFO evm_eth_compliance::statetest::runner: UC : "jumpNonConst"
2023-01-27T07:48:58.216712Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1587383,
    events_root: None,
}
2023-01-27T07:48:58.216714Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=22): jumpdest 0 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T07:48:58.216726Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:58.216729Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "jumpNonConst"::London::0
2023-01-27T07:48:58.216731Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/jumpNonConst.json"
2023-01-27T07:48:58.216735Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:58.216737Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:58.216845Z  INFO evm_eth_compliance::statetest::runner: UC : "jumpNonConst"
2023-01-27T07:48:58.216850Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1587383,
    events_root: None,
}
2023-01-27T07:48:58.216853Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=22): jumpdest 0 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T07:48:58.216861Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:58.216863Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "jumpNonConst"::London::0
2023-01-27T07:48:58.216865Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/jumpNonConst.json"
2023-01-27T07:48:58.216868Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:58.216869Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:58.216963Z  INFO evm_eth_compliance::statetest::runner: UC : "jumpNonConst"
2023-01-27T07:48:58.216967Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1587383,
    events_root: None,
}
2023-01-27T07:48:58.216971Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=22): jumpdest 0 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T07:48:58.216979Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:58.216981Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "jumpNonConst"::Merge::0
2023-01-27T07:48:58.216983Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/jumpNonConst.json"
2023-01-27T07:48:58.216985Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:58.216987Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:58.217076Z  INFO evm_eth_compliance::statetest::runner: UC : "jumpNonConst"
2023-01-27T07:48:58.217080Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1587383,
    events_root: None,
}
2023-01-27T07:48:58.217083Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=22): jumpdest 0 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T07:48:58.217091Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:58.217094Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "jumpNonConst"::Merge::0
2023-01-27T07:48:58.217096Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/jumpNonConst.json"
2023-01-27T07:48:58.217098Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:58.217100Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:58.217187Z  INFO evm_eth_compliance::statetest::runner: UC : "jumpNonConst"
2023-01-27T07:48:58.217191Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1587383,
    events_root: None,
}
2023-01-27T07:48:58.217193Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=22): jumpdest 0 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-27T07:48:58.219103Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:383.499008ms
2023-01-27T07:48:58.515284Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/jumpiNonConst.json", Total Files :: 1
2023-01-27T07:48:58.578236Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:48:58.578375Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:58.578379Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:48:58.578432Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:58.578504Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:58.578507Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "jumpiNonConst"::Istanbul::0
2023-01-27T07:48:58.578510Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/jumpiNonConst.json"
2023-01-27T07:48:58.578513Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:58.578514Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:58.945544Z  INFO evm_eth_compliance::statetest::runner: UC : "jumpiNonConst"
2023-01-27T07:48:58.945560Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1615113,
    events_root: None,
}
2023-01-27T07:48:58.945571Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:58.945576Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "jumpiNonConst"::Istanbul::0
2023-01-27T07:48:58.945578Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/jumpiNonConst.json"
2023-01-27T07:48:58.945581Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:58.945583Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:58.945694Z  INFO evm_eth_compliance::statetest::runner: UC : "jumpiNonConst"
2023-01-27T07:48:58.945699Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1615113,
    events_root: None,
}
2023-01-27T07:48:58.945704Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:58.945707Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "jumpiNonConst"::Berlin::0
2023-01-27T07:48:58.945709Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/jumpiNonConst.json"
2023-01-27T07:48:58.945711Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:58.945712Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:58.945807Z  INFO evm_eth_compliance::statetest::runner: UC : "jumpiNonConst"
2023-01-27T07:48:58.945811Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1615113,
    events_root: None,
}
2023-01-27T07:48:58.945816Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:58.945818Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "jumpiNonConst"::Berlin::0
2023-01-27T07:48:58.945821Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/jumpiNonConst.json"
2023-01-27T07:48:58.945823Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:58.945825Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:58.945917Z  INFO evm_eth_compliance::statetest::runner: UC : "jumpiNonConst"
2023-01-27T07:48:58.945921Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1615113,
    events_root: None,
}
2023-01-27T07:48:58.945926Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:58.945928Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "jumpiNonConst"::London::0
2023-01-27T07:48:58.945930Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/jumpiNonConst.json"
2023-01-27T07:48:58.945932Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:58.945934Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:58.946027Z  INFO evm_eth_compliance::statetest::runner: UC : "jumpiNonConst"
2023-01-27T07:48:58.946031Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1615113,
    events_root: None,
}
2023-01-27T07:48:58.946036Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:58.946038Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "jumpiNonConst"::London::0
2023-01-27T07:48:58.946040Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/jumpiNonConst.json"
2023-01-27T07:48:58.946042Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:58.946044Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:58.946136Z  INFO evm_eth_compliance::statetest::runner: UC : "jumpiNonConst"
2023-01-27T07:48:58.946140Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1615113,
    events_root: None,
}
2023-01-27T07:48:58.946145Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:58.946147Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "jumpiNonConst"::Merge::0
2023-01-27T07:48:58.946149Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/jumpiNonConst.json"
2023-01-27T07:48:58.946151Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:58.946153Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:58.946284Z  INFO evm_eth_compliance::statetest::runner: UC : "jumpiNonConst"
2023-01-27T07:48:58.946290Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1615113,
    events_root: None,
}
2023-01-27T07:48:58.946297Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:58.946299Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "jumpiNonConst"::Merge::0
2023-01-27T07:48:58.946301Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/jumpiNonConst.json"
2023-01-27T07:48:58.946305Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:58.946308Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:58.946418Z  INFO evm_eth_compliance::statetest::runner: UC : "jumpiNonConst"
2023-01-27T07:48:58.946422Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1615113,
    events_root: None,
}
2023-01-27T07:48:58.948250Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:368.195513ms
2023-01-27T07:48:59.225539Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/log0NonConst.json", Total Files :: 1
2023-01-27T07:48:59.256304Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:48:59.256461Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:59.256465Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:48:59.256522Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:59.256603Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:59.256607Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log0NonConst"::Istanbul::0
2023-01-27T07:48:59.256610Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/log0NonConst.json"
2023-01-27T07:48:59.256613Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:59.256615Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:59.623980Z  INFO evm_eth_compliance::statetest::runner: UC : "log0NonConst"
2023-01-27T07:48:59.624003Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1635789,
    events_root: Some(
        Cid {
            version: V1,
            codec: 113,
            hash: Multihash {
                code: 45600,
                size: 32,
                digest: [
                    53,
                    21,
                    60,
                    179,
                    36,
                    197,
                    153,
                    156,
                    251,
                    156,
                    142,
                    154,
                    202,
                    227,
                    230,
                    233,
                    12,
                    124,
                    236,
                    111,
                    250,
                    173,
                    178,
                    181,
                    10,
                    202,
                    188,
                    32,
                    222,
                    31,
                    215,
                    20,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    ),
}
2023-01-27T07:48:59.624041Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:59.624046Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log0NonConst"::Istanbul::0
2023-01-27T07:48:59.624048Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/log0NonConst.json"
2023-01-27T07:48:59.624052Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:59.624053Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:59.624205Z  INFO evm_eth_compliance::statetest::runner: UC : "log0NonConst"
2023-01-27T07:48:59.624211Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1635789,
    events_root: Some(
        Cid {
            version: V1,
            codec: 113,
            hash: Multihash {
                code: 45600,
                size: 32,
                digest: [
                    53,
                    21,
                    60,
                    179,
                    36,
                    197,
                    153,
                    156,
                    251,
                    156,
                    142,
                    154,
                    202,
                    227,
                    230,
                    233,
                    12,
                    124,
                    236,
                    111,
                    250,
                    173,
                    178,
                    181,
                    10,
                    202,
                    188,
                    32,
                    222,
                    31,
                    215,
                    20,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    ),
}
2023-01-27T07:48:59.624239Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:59.624241Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log0NonConst"::Berlin::0
2023-01-27T07:48:59.624244Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/log0NonConst.json"
2023-01-27T07:48:59.624247Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:59.624248Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:59.624381Z  INFO evm_eth_compliance::statetest::runner: UC : "log0NonConst"
2023-01-27T07:48:59.624386Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1635789,
    events_root: Some(
        Cid {
            version: V1,
            codec: 113,
            hash: Multihash {
                code: 45600,
                size: 32,
                digest: [
                    53,
                    21,
                    60,
                    179,
                    36,
                    197,
                    153,
                    156,
                    251,
                    156,
                    142,
                    154,
                    202,
                    227,
                    230,
                    233,
                    12,
                    124,
                    236,
                    111,
                    250,
                    173,
                    178,
                    181,
                    10,
                    202,
                    188,
                    32,
                    222,
                    31,
                    215,
                    20,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    ),
}
2023-01-27T07:48:59.624415Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:48:59.624417Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log0NonConst"::Berlin::0
2023-01-27T07:48:59.624419Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/log0NonConst.json"
2023-01-27T07:48:59.624422Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:59.624424Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:59.624558Z  INFO evm_eth_compliance::statetest::runner: UC : "log0NonConst"
2023-01-27T07:48:59.624564Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1635789,
    events_root: Some(
        Cid {
            version: V1,
            codec: 113,
            hash: Multihash {
                code: 45600,
                size: 32,
                digest: [
                    53,
                    21,
                    60,
                    179,
                    36,
                    197,
                    153,
                    156,
                    251,
                    156,
                    142,
                    154,
                    202,
                    227,
                    230,
                    233,
                    12,
                    124,
                    236,
                    111,
                    250,
                    173,
                    178,
                    181,
                    10,
                    202,
                    188,
                    32,
                    222,
                    31,
                    215,
                    20,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    ),
}
2023-01-27T07:48:59.624593Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:59.624596Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log0NonConst"::London::0
2023-01-27T07:48:59.624600Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/log0NonConst.json"
2023-01-27T07:48:59.624603Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:59.624606Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:59.624733Z  INFO evm_eth_compliance::statetest::runner: UC : "log0NonConst"
2023-01-27T07:48:59.624739Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1635789,
    events_root: Some(
        Cid {
            version: V1,
            codec: 113,
            hash: Multihash {
                code: 45600,
                size: 32,
                digest: [
                    53,
                    21,
                    60,
                    179,
                    36,
                    197,
                    153,
                    156,
                    251,
                    156,
                    142,
                    154,
                    202,
                    227,
                    230,
                    233,
                    12,
                    124,
                    236,
                    111,
                    250,
                    173,
                    178,
                    181,
                    10,
                    202,
                    188,
                    32,
                    222,
                    31,
                    215,
                    20,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    ),
}
2023-01-27T07:48:59.624766Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:48:59.624768Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log0NonConst"::London::0
2023-01-27T07:48:59.624770Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/log0NonConst.json"
2023-01-27T07:48:59.624774Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:59.624775Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:59.624905Z  INFO evm_eth_compliance::statetest::runner: UC : "log0NonConst"
2023-01-27T07:48:59.624910Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1635789,
    events_root: Some(
        Cid {
            version: V1,
            codec: 113,
            hash: Multihash {
                code: 45600,
                size: 32,
                digest: [
                    53,
                    21,
                    60,
                    179,
                    36,
                    197,
                    153,
                    156,
                    251,
                    156,
                    142,
                    154,
                    202,
                    227,
                    230,
                    233,
                    12,
                    124,
                    236,
                    111,
                    250,
                    173,
                    178,
                    181,
                    10,
                    202,
                    188,
                    32,
                    222,
                    31,
                    215,
                    20,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    ),
}
2023-01-27T07:48:59.624938Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:59.624941Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log0NonConst"::Merge::0
2023-01-27T07:48:59.624943Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/log0NonConst.json"
2023-01-27T07:48:59.624945Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:59.624947Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:59.625070Z  INFO evm_eth_compliance::statetest::runner: UC : "log0NonConst"
2023-01-27T07:48:59.625074Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1635789,
    events_root: Some(
        Cid {
            version: V1,
            codec: 113,
            hash: Multihash {
                code: 45600,
                size: 32,
                digest: [
                    53,
                    21,
                    60,
                    179,
                    36,
                    197,
                    153,
                    156,
                    251,
                    156,
                    142,
                    154,
                    202,
                    227,
                    230,
                    233,
                    12,
                    124,
                    236,
                    111,
                    250,
                    173,
                    178,
                    181,
                    10,
                    202,
                    188,
                    32,
                    222,
                    31,
                    215,
                    20,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    ),
}
2023-01-27T07:48:59.625101Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:48:59.625104Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log0NonConst"::Merge::0
2023-01-27T07:48:59.625106Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/log0NonConst.json"
2023-01-27T07:48:59.625109Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:59.625110Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:48:59.625228Z  INFO evm_eth_compliance::statetest::runner: UC : "log0NonConst"
2023-01-27T07:48:59.625233Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1635789,
    events_root: Some(
        Cid {
            version: V1,
            codec: 113,
            hash: Multihash {
                code: 45600,
                size: 32,
                digest: [
                    53,
                    21,
                    60,
                    179,
                    36,
                    197,
                    153,
                    156,
                    251,
                    156,
                    142,
                    154,
                    202,
                    227,
                    230,
                    233,
                    12,
                    124,
                    236,
                    111,
                    250,
                    173,
                    178,
                    181,
                    10,
                    202,
                    188,
                    32,
                    222,
                    31,
                    215,
                    20,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    ),
}
2023-01-27T07:48:59.626977Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:368.955931ms
2023-01-27T07:48:59.920113Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/log1NonConst.json", Total Files :: 1
2023-01-27T07:48:59.951444Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:48:59.951597Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:59.951601Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:48:59.951658Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:48:59.951740Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:48:59.951743Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1NonConst"::Istanbul::0
2023-01-27T07:48:59.951745Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/log1NonConst.json"
2023-01-27T07:48:59.951749Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:48:59.951750Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:00.320651Z  INFO evm_eth_compliance::statetest::runner: UC : "log1NonConst"
2023-01-27T07:49:00.320670Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1693441,
    events_root: Some(
        Cid {
            version: V1,
            codec: 113,
            hash: Multihash {
                code: 45600,
                size: 32,
                digest: [
                    1,
                    57,
                    101,
                    5,
                    198,
                    181,
                    85,
                    109,
                    46,
                    33,
                    154,
                    78,
                    193,
                    6,
                    141,
                    56,
                    31,
                    86,
                    70,
                    65,
                    47,
                    69,
                    6,
                    89,
                    210,
                    17,
                    46,
                    212,
                    17,
                    151,
                    247,
                    69,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    ),
}
2023-01-27T07:49:00.320711Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:00.320716Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1NonConst"::Istanbul::0
2023-01-27T07:49:00.320719Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/log1NonConst.json"
2023-01-27T07:49:00.320723Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:00.320725Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:00.320872Z  INFO evm_eth_compliance::statetest::runner: UC : "log1NonConst"
2023-01-27T07:49:00.320877Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1693441,
    events_root: Some(
        Cid {
            version: V1,
            codec: 113,
            hash: Multihash {
                code: 45600,
                size: 32,
                digest: [
                    1,
                    57,
                    101,
                    5,
                    198,
                    181,
                    85,
                    109,
                    46,
                    33,
                    154,
                    78,
                    193,
                    6,
                    141,
                    56,
                    31,
                    86,
                    70,
                    65,
                    47,
                    69,
                    6,
                    89,
                    210,
                    17,
                    46,
                    212,
                    17,
                    151,
                    247,
                    69,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    ),
}
2023-01-27T07:49:00.320908Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:00.320911Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1NonConst"::Berlin::0
2023-01-27T07:49:00.320913Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/log1NonConst.json"
2023-01-27T07:49:00.320917Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:00.320919Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:00.321050Z  INFO evm_eth_compliance::statetest::runner: UC : "log1NonConst"
2023-01-27T07:49:00.321061Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1693441,
    events_root: Some(
        Cid {
            version: V1,
            codec: 113,
            hash: Multihash {
                code: 45600,
                size: 32,
                digest: [
                    1,
                    57,
                    101,
                    5,
                    198,
                    181,
                    85,
                    109,
                    46,
                    33,
                    154,
                    78,
                    193,
                    6,
                    141,
                    56,
                    31,
                    86,
                    70,
                    65,
                    47,
                    69,
                    6,
                    89,
                    210,
                    17,
                    46,
                    212,
                    17,
                    151,
                    247,
                    69,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    ),
}
2023-01-27T07:49:00.321091Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:00.321094Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1NonConst"::Berlin::0
2023-01-27T07:49:00.321096Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/log1NonConst.json"
2023-01-27T07:49:00.321099Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:00.321101Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:00.321235Z  INFO evm_eth_compliance::statetest::runner: UC : "log1NonConst"
2023-01-27T07:49:00.321240Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1693441,
    events_root: Some(
        Cid {
            version: V1,
            codec: 113,
            hash: Multihash {
                code: 45600,
                size: 32,
                digest: [
                    1,
                    57,
                    101,
                    5,
                    198,
                    181,
                    85,
                    109,
                    46,
                    33,
                    154,
                    78,
                    193,
                    6,
                    141,
                    56,
                    31,
                    86,
                    70,
                    65,
                    47,
                    69,
                    6,
                    89,
                    210,
                    17,
                    46,
                    212,
                    17,
                    151,
                    247,
                    69,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    ),
}
2023-01-27T07:49:00.321271Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:00.321274Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1NonConst"::London::0
2023-01-27T07:49:00.321276Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/log1NonConst.json"
2023-01-27T07:49:00.321280Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:00.321282Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:00.321424Z  INFO evm_eth_compliance::statetest::runner: UC : "log1NonConst"
2023-01-27T07:49:00.321429Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1693441,
    events_root: Some(
        Cid {
            version: V1,
            codec: 113,
            hash: Multihash {
                code: 45600,
                size: 32,
                digest: [
                    1,
                    57,
                    101,
                    5,
                    198,
                    181,
                    85,
                    109,
                    46,
                    33,
                    154,
                    78,
                    193,
                    6,
                    141,
                    56,
                    31,
                    86,
                    70,
                    65,
                    47,
                    69,
                    6,
                    89,
                    210,
                    17,
                    46,
                    212,
                    17,
                    151,
                    247,
                    69,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    ),
}
2023-01-27T07:49:00.321461Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:00.321463Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1NonConst"::London::0
2023-01-27T07:49:00.321466Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/log1NonConst.json"
2023-01-27T07:49:00.321469Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:00.321471Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:00.321601Z  INFO evm_eth_compliance::statetest::runner: UC : "log1NonConst"
2023-01-27T07:49:00.321606Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1693441,
    events_root: Some(
        Cid {
            version: V1,
            codec: 113,
            hash: Multihash {
                code: 45600,
                size: 32,
                digest: [
                    1,
                    57,
                    101,
                    5,
                    198,
                    181,
                    85,
                    109,
                    46,
                    33,
                    154,
                    78,
                    193,
                    6,
                    141,
                    56,
                    31,
                    86,
                    70,
                    65,
                    47,
                    69,
                    6,
                    89,
                    210,
                    17,
                    46,
                    212,
                    17,
                    151,
                    247,
                    69,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    ),
}
2023-01-27T07:49:00.321637Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:00.321640Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1NonConst"::Merge::0
2023-01-27T07:49:00.321642Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/log1NonConst.json"
2023-01-27T07:49:00.321646Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:00.321647Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:00.321777Z  INFO evm_eth_compliance::statetest::runner: UC : "log1NonConst"
2023-01-27T07:49:00.321782Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1693441,
    events_root: Some(
        Cid {
            version: V1,
            codec: 113,
            hash: Multihash {
                code: 45600,
                size: 32,
                digest: [
                    1,
                    57,
                    101,
                    5,
                    198,
                    181,
                    85,
                    109,
                    46,
                    33,
                    154,
                    78,
                    193,
                    6,
                    141,
                    56,
                    31,
                    86,
                    70,
                    65,
                    47,
                    69,
                    6,
                    89,
                    210,
                    17,
                    46,
                    212,
                    17,
                    151,
                    247,
                    69,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    ),
}
2023-01-27T07:49:00.321812Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:00.321815Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log1NonConst"::Merge::0
2023-01-27T07:49:00.321818Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/log1NonConst.json"
2023-01-27T07:49:00.321821Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:00.321823Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:00.321951Z  INFO evm_eth_compliance::statetest::runner: UC : "log1NonConst"
2023-01-27T07:49:00.321956Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1693441,
    events_root: Some(
        Cid {
            version: V1,
            codec: 113,
            hash: Multihash {
                code: 45600,
                size: 32,
                digest: [
                    1,
                    57,
                    101,
                    5,
                    198,
                    181,
                    85,
                    109,
                    46,
                    33,
                    154,
                    78,
                    193,
                    6,
                    141,
                    56,
                    31,
                    86,
                    70,
                    65,
                    47,
                    69,
                    6,
                    89,
                    210,
                    17,
                    46,
                    212,
                    17,
                    151,
                    247,
                    69,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    ),
}
2023-01-27T07:49:00.324282Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:370.547548ms
2023-01-27T07:49:00.608646Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/log2NonConst.json", Total Files :: 1
2023-01-27T07:49:00.648515Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:49:00.648647Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:00.648651Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:49:00.648703Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:00.648773Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:00.648776Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2NonConst"::Istanbul::0
2023-01-27T07:49:00.648779Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/log2NonConst.json"
2023-01-27T07:49:00.648782Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:00.648784Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:01.065753Z  INFO evm_eth_compliance::statetest::runner: UC : "log2NonConst"
2023-01-27T07:49:01.065767Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1752097,
    events_root: Some(
        Cid {
            version: V1,
            codec: 113,
            hash: Multihash {
                code: 45600,
                size: 32,
                digest: [
                    98,
                    244,
                    183,
                    240,
                    134,
                    235,
                    6,
                    228,
                    237,
                    243,
                    38,
                    152,
                    25,
                    70,
                    103,
                    4,
                    34,
                    201,
                    130,
                    21,
                    209,
                    40,
                    248,
                    47,
                    0,
                    102,
                    72,
                    113,
                    18,
                    56,
                    199,
                    150,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    ),
}
2023-01-27T07:49:01.065798Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:01.065802Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2NonConst"::Istanbul::0
2023-01-27T07:49:01.065804Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/log2NonConst.json"
2023-01-27T07:49:01.065807Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:01.065808Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:01.065959Z  INFO evm_eth_compliance::statetest::runner: UC : "log2NonConst"
2023-01-27T07:49:01.065963Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1752097,
    events_root: Some(
        Cid {
            version: V1,
            codec: 113,
            hash: Multihash {
                code: 45600,
                size: 32,
                digest: [
                    98,
                    244,
                    183,
                    240,
                    134,
                    235,
                    6,
                    228,
                    237,
                    243,
                    38,
                    152,
                    25,
                    70,
                    103,
                    4,
                    34,
                    201,
                    130,
                    21,
                    209,
                    40,
                    248,
                    47,
                    0,
                    102,
                    72,
                    113,
                    18,
                    56,
                    199,
                    150,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    ),
}
2023-01-27T07:49:01.065987Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:01.065989Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2NonConst"::Berlin::0
2023-01-27T07:49:01.065991Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/log2NonConst.json"
2023-01-27T07:49:01.065993Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:01.065994Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:01.066104Z  INFO evm_eth_compliance::statetest::runner: UC : "log2NonConst"
2023-01-27T07:49:01.066108Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1752097,
    events_root: Some(
        Cid {
            version: V1,
            codec: 113,
            hash: Multihash {
                code: 45600,
                size: 32,
                digest: [
                    98,
                    244,
                    183,
                    240,
                    134,
                    235,
                    6,
                    228,
                    237,
                    243,
                    38,
                    152,
                    25,
                    70,
                    103,
                    4,
                    34,
                    201,
                    130,
                    21,
                    209,
                    40,
                    248,
                    47,
                    0,
                    102,
                    72,
                    113,
                    18,
                    56,
                    199,
                    150,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    ),
}
2023-01-27T07:49:01.066130Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:01.066132Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2NonConst"::Berlin::0
2023-01-27T07:49:01.066134Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/log2NonConst.json"
2023-01-27T07:49:01.066136Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:01.066137Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:01.066247Z  INFO evm_eth_compliance::statetest::runner: UC : "log2NonConst"
2023-01-27T07:49:01.066251Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1752097,
    events_root: Some(
        Cid {
            version: V1,
            codec: 113,
            hash: Multihash {
                code: 45600,
                size: 32,
                digest: [
                    98,
                    244,
                    183,
                    240,
                    134,
                    235,
                    6,
                    228,
                    237,
                    243,
                    38,
                    152,
                    25,
                    70,
                    103,
                    4,
                    34,
                    201,
                    130,
                    21,
                    209,
                    40,
                    248,
                    47,
                    0,
                    102,
                    72,
                    113,
                    18,
                    56,
                    199,
                    150,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    ),
}
2023-01-27T07:49:01.066273Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:01.066275Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2NonConst"::London::0
2023-01-27T07:49:01.066277Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/log2NonConst.json"
2023-01-27T07:49:01.066279Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:01.066281Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:01.066388Z  INFO evm_eth_compliance::statetest::runner: UC : "log2NonConst"
2023-01-27T07:49:01.066393Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1752097,
    events_root: Some(
        Cid {
            version: V1,
            codec: 113,
            hash: Multihash {
                code: 45600,
                size: 32,
                digest: [
                    98,
                    244,
                    183,
                    240,
                    134,
                    235,
                    6,
                    228,
                    237,
                    243,
                    38,
                    152,
                    25,
                    70,
                    103,
                    4,
                    34,
                    201,
                    130,
                    21,
                    209,
                    40,
                    248,
                    47,
                    0,
                    102,
                    72,
                    113,
                    18,
                    56,
                    199,
                    150,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    ),
}
2023-01-27T07:49:01.066415Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:01.066417Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2NonConst"::London::0
2023-01-27T07:49:01.066419Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/log2NonConst.json"
2023-01-27T07:49:01.066421Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:01.066422Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:01.066530Z  INFO evm_eth_compliance::statetest::runner: UC : "log2NonConst"
2023-01-27T07:49:01.066534Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1752097,
    events_root: Some(
        Cid {
            version: V1,
            codec: 113,
            hash: Multihash {
                code: 45600,
                size: 32,
                digest: [
                    98,
                    244,
                    183,
                    240,
                    134,
                    235,
                    6,
                    228,
                    237,
                    243,
                    38,
                    152,
                    25,
                    70,
                    103,
                    4,
                    34,
                    201,
                    130,
                    21,
                    209,
                    40,
                    248,
                    47,
                    0,
                    102,
                    72,
                    113,
                    18,
                    56,
                    199,
                    150,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    ),
}
2023-01-27T07:49:01.066555Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:01.066557Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2NonConst"::Merge::0
2023-01-27T07:49:01.066559Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/log2NonConst.json"
2023-01-27T07:49:01.066561Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:01.066562Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:01.066670Z  INFO evm_eth_compliance::statetest::runner: UC : "log2NonConst"
2023-01-27T07:49:01.066674Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1752097,
    events_root: Some(
        Cid {
            version: V1,
            codec: 113,
            hash: Multihash {
                code: 45600,
                size: 32,
                digest: [
                    98,
                    244,
                    183,
                    240,
                    134,
                    235,
                    6,
                    228,
                    237,
                    243,
                    38,
                    152,
                    25,
                    70,
                    103,
                    4,
                    34,
                    201,
                    130,
                    21,
                    209,
                    40,
                    248,
                    47,
                    0,
                    102,
                    72,
                    113,
                    18,
                    56,
                    199,
                    150,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    ),
}
2023-01-27T07:49:01.066698Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:01.066700Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log2NonConst"::Merge::0
2023-01-27T07:49:01.066702Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/log2NonConst.json"
2023-01-27T07:49:01.066705Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:01.066706Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:01.066817Z  INFO evm_eth_compliance::statetest::runner: UC : "log2NonConst"
2023-01-27T07:49:01.066821Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1752097,
    events_root: Some(
        Cid {
            version: V1,
            codec: 113,
            hash: Multihash {
                code: 45600,
                size: 32,
                digest: [
                    98,
                    244,
                    183,
                    240,
                    134,
                    235,
                    6,
                    228,
                    237,
                    243,
                    38,
                    152,
                    25,
                    70,
                    103,
                    4,
                    34,
                    201,
                    130,
                    21,
                    209,
                    40,
                    248,
                    47,
                    0,
                    102,
                    72,
                    113,
                    18,
                    56,
                    199,
                    150,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    ),
}
2023-01-27T07:49:01.068267Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:418.334603ms
2023-01-27T07:49:01.358138Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/log3NonConst.json", Total Files :: 1
2023-01-27T07:49:01.423253Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:49:01.423555Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:01.423563Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:49:01.423650Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:01.423759Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:01.423764Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3NonConst"::Istanbul::0
2023-01-27T07:49:01.423767Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/log3NonConst.json"
2023-01-27T07:49:01.423772Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:01.423774Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:01.783928Z  INFO evm_eth_compliance::statetest::runner: UC : "log3NonConst"
2023-01-27T07:49:01.783945Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1810630,
    events_root: Some(
        Cid {
            version: V1,
            codec: 113,
            hash: Multihash {
                code: 45600,
                size: 32,
                digest: [
                    161,
                    132,
                    72,
                    138,
                    141,
                    235,
                    68,
                    205,
                    155,
                    140,
                    186,
                    224,
                    93,
                    204,
                    21,
                    59,
                    95,
                    208,
                    216,
                    0,
                    75,
                    39,
                    99,
                    57,
                    123,
                    160,
                    28,
                    129,
                    110,
                    191,
                    82,
                    86,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    ),
}
2023-01-27T07:49:01.783975Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:01.783979Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3NonConst"::Istanbul::0
2023-01-27T07:49:01.783980Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/log3NonConst.json"
2023-01-27T07:49:01.783983Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:01.783984Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:01.784132Z  INFO evm_eth_compliance::statetest::runner: UC : "log3NonConst"
2023-01-27T07:49:01.784136Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1810630,
    events_root: Some(
        Cid {
            version: V1,
            codec: 113,
            hash: Multihash {
                code: 45600,
                size: 32,
                digest: [
                    161,
                    132,
                    72,
                    138,
                    141,
                    235,
                    68,
                    205,
                    155,
                    140,
                    186,
                    224,
                    93,
                    204,
                    21,
                    59,
                    95,
                    208,
                    216,
                    0,
                    75,
                    39,
                    99,
                    57,
                    123,
                    160,
                    28,
                    129,
                    110,
                    191,
                    82,
                    86,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    ),
}
2023-01-27T07:49:01.784158Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:01.784161Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3NonConst"::Berlin::0
2023-01-27T07:49:01.784162Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/log3NonConst.json"
2023-01-27T07:49:01.784164Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:01.784166Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:01.784273Z  INFO evm_eth_compliance::statetest::runner: UC : "log3NonConst"
2023-01-27T07:49:01.784277Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1810630,
    events_root: Some(
        Cid {
            version: V1,
            codec: 113,
            hash: Multihash {
                code: 45600,
                size: 32,
                digest: [
                    161,
                    132,
                    72,
                    138,
                    141,
                    235,
                    68,
                    205,
                    155,
                    140,
                    186,
                    224,
                    93,
                    204,
                    21,
                    59,
                    95,
                    208,
                    216,
                    0,
                    75,
                    39,
                    99,
                    57,
                    123,
                    160,
                    28,
                    129,
                    110,
                    191,
                    82,
                    86,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    ),
}
2023-01-27T07:49:01.784299Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:01.784301Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3NonConst"::Berlin::0
2023-01-27T07:49:01.784303Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/log3NonConst.json"
2023-01-27T07:49:01.784305Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:01.784306Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:01.784449Z  INFO evm_eth_compliance::statetest::runner: UC : "log3NonConst"
2023-01-27T07:49:01.784455Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1810630,
    events_root: Some(
        Cid {
            version: V1,
            codec: 113,
            hash: Multihash {
                code: 45600,
                size: 32,
                digest: [
                    161,
                    132,
                    72,
                    138,
                    141,
                    235,
                    68,
                    205,
                    155,
                    140,
                    186,
                    224,
                    93,
                    204,
                    21,
                    59,
                    95,
                    208,
                    216,
                    0,
                    75,
                    39,
                    99,
                    57,
                    123,
                    160,
                    28,
                    129,
                    110,
                    191,
                    82,
                    86,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    ),
}
2023-01-27T07:49:01.784488Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:01.784491Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3NonConst"::London::0
2023-01-27T07:49:01.784493Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/log3NonConst.json"
2023-01-27T07:49:01.784496Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:01.784498Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:01.784611Z  INFO evm_eth_compliance::statetest::runner: UC : "log3NonConst"
2023-01-27T07:49:01.784615Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1810630,
    events_root: Some(
        Cid {
            version: V1,
            codec: 113,
            hash: Multihash {
                code: 45600,
                size: 32,
                digest: [
                    161,
                    132,
                    72,
                    138,
                    141,
                    235,
                    68,
                    205,
                    155,
                    140,
                    186,
                    224,
                    93,
                    204,
                    21,
                    59,
                    95,
                    208,
                    216,
                    0,
                    75,
                    39,
                    99,
                    57,
                    123,
                    160,
                    28,
                    129,
                    110,
                    191,
                    82,
                    86,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    ),
}
2023-01-27T07:49:01.784636Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:01.784638Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3NonConst"::London::0
2023-01-27T07:49:01.784639Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/log3NonConst.json"
2023-01-27T07:49:01.784642Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:01.784643Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:01.784748Z  INFO evm_eth_compliance::statetest::runner: UC : "log3NonConst"
2023-01-27T07:49:01.784752Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1810630,
    events_root: Some(
        Cid {
            version: V1,
            codec: 113,
            hash: Multihash {
                code: 45600,
                size: 32,
                digest: [
                    161,
                    132,
                    72,
                    138,
                    141,
                    235,
                    68,
                    205,
                    155,
                    140,
                    186,
                    224,
                    93,
                    204,
                    21,
                    59,
                    95,
                    208,
                    216,
                    0,
                    75,
                    39,
                    99,
                    57,
                    123,
                    160,
                    28,
                    129,
                    110,
                    191,
                    82,
                    86,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    ),
}
2023-01-27T07:49:01.784773Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:01.784775Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3NonConst"::Merge::0
2023-01-27T07:49:01.784777Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/log3NonConst.json"
2023-01-27T07:49:01.784779Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:01.784781Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:01.784927Z  INFO evm_eth_compliance::statetest::runner: UC : "log3NonConst"
2023-01-27T07:49:01.784931Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1810630,
    events_root: Some(
        Cid {
            version: V1,
            codec: 113,
            hash: Multihash {
                code: 45600,
                size: 32,
                digest: [
                    161,
                    132,
                    72,
                    138,
                    141,
                    235,
                    68,
                    205,
                    155,
                    140,
                    186,
                    224,
                    93,
                    204,
                    21,
                    59,
                    95,
                    208,
                    216,
                    0,
                    75,
                    39,
                    99,
                    57,
                    123,
                    160,
                    28,
                    129,
                    110,
                    191,
                    82,
                    86,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    ),
}
2023-01-27T07:49:01.784952Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:01.784954Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "log3NonConst"::Merge::0
2023-01-27T07:49:01.784956Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/log3NonConst.json"
2023-01-27T07:49:01.784958Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:01.784959Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:01.785073Z  INFO evm_eth_compliance::statetest::runner: UC : "log3NonConst"
2023-01-27T07:49:01.785076Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1810630,
    events_root: Some(
        Cid {
            version: V1,
            codec: 113,
            hash: Multihash {
                code: 45600,
                size: 32,
                digest: [
                    161,
                    132,
                    72,
                    138,
                    141,
                    235,
                    68,
                    205,
                    155,
                    140,
                    186,
                    224,
                    93,
                    204,
                    21,
                    59,
                    95,
                    208,
                    216,
                    0,
                    75,
                    39,
                    99,
                    57,
                    123,
                    160,
                    28,
                    129,
                    110,
                    191,
                    82,
                    86,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            },
        },
    ),
}
2023-01-27T07:49:01.786708Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:361.849724ms
2023-01-27T07:49:02.058564Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/ltNonConst.json", Total Files :: 1
2023-01-27T07:49:02.112665Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:49:02.112813Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:02.112817Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:49:02.112872Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:02.112946Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:02.112949Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ltNonConst"::Istanbul::0
2023-01-27T07:49:02.112952Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/ltNonConst.json"
2023-01-27T07:49:02.112954Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:02.112956Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:02.473274Z  INFO evm_eth_compliance::statetest::runner: UC : "ltNonConst"
2023-01-27T07:49:02.473336Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618908,
    events_root: None,
}
2023-01-27T07:49:02.473359Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:02.473365Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ltNonConst"::Istanbul::0
2023-01-27T07:49:02.473368Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/ltNonConst.json"
2023-01-27T07:49:02.473371Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:02.473373Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:02.473555Z  INFO evm_eth_compliance::statetest::runner: UC : "ltNonConst"
2023-01-27T07:49:02.473572Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618908,
    events_root: None,
}
2023-01-27T07:49:02.473588Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:02.473597Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ltNonConst"::Berlin::0
2023-01-27T07:49:02.473604Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/ltNonConst.json"
2023-01-27T07:49:02.473612Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:02.473620Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:02.473753Z  INFO evm_eth_compliance::statetest::runner: UC : "ltNonConst"
2023-01-27T07:49:02.473768Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618908,
    events_root: None,
}
2023-01-27T07:49:02.473783Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:02.473791Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ltNonConst"::Berlin::0
2023-01-27T07:49:02.473798Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/ltNonConst.json"
2023-01-27T07:49:02.473808Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:02.473814Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:02.473947Z  INFO evm_eth_compliance::statetest::runner: UC : "ltNonConst"
2023-01-27T07:49:02.473962Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618908,
    events_root: None,
}
2023-01-27T07:49:02.473977Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:02.473986Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ltNonConst"::London::0
2023-01-27T07:49:02.473994Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/ltNonConst.json"
2023-01-27T07:49:02.474002Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:02.474008Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:02.474121Z  INFO evm_eth_compliance::statetest::runner: UC : "ltNonConst"
2023-01-27T07:49:02.474125Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618908,
    events_root: None,
}
2023-01-27T07:49:02.474132Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:02.474134Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ltNonConst"::London::0
2023-01-27T07:49:02.474135Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/ltNonConst.json"
2023-01-27T07:49:02.474138Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:02.474139Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:02.474234Z  INFO evm_eth_compliance::statetest::runner: UC : "ltNonConst"
2023-01-27T07:49:02.474238Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618908,
    events_root: None,
}
2023-01-27T07:49:02.474244Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:02.474246Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ltNonConst"::Merge::0
2023-01-27T07:49:02.474248Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/ltNonConst.json"
2023-01-27T07:49:02.474250Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:02.474252Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:02.474343Z  INFO evm_eth_compliance::statetest::runner: UC : "ltNonConst"
2023-01-27T07:49:02.474346Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618908,
    events_root: None,
}
2023-01-27T07:49:02.474353Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:02.474355Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ltNonConst"::Merge::0
2023-01-27T07:49:02.474357Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/ltNonConst.json"
2023-01-27T07:49:02.474359Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:02.474361Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:02.474451Z  INFO evm_eth_compliance::statetest::runner: UC : "ltNonConst"
2023-01-27T07:49:02.474455Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618908,
    events_root: None,
}
2023-01-27T07:49:02.476709Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:361.801184ms
2023-01-27T07:49:02.764228Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mloadNonConst.json", Total Files :: 1
2023-01-27T07:49:02.806610Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:49:02.806743Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:02.806747Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:49:02.806798Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:02.806867Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:02.806870Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mloadNonConst"::Istanbul::0
2023-01-27T07:49:02.806873Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mloadNonConst.json"
2023-01-27T07:49:02.806876Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:02.806877Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:03.160129Z  INFO evm_eth_compliance::statetest::runner: UC : "mloadNonConst"
2023-01-27T07:49:03.160142Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1574890,
    events_root: None,
}
2023-01-27T07:49:03.160153Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:03.160156Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mloadNonConst"::Istanbul::0
2023-01-27T07:49:03.160158Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mloadNonConst.json"
2023-01-27T07:49:03.160161Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:03.160163Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:03.160284Z  INFO evm_eth_compliance::statetest::runner: UC : "mloadNonConst"
2023-01-27T07:49:03.160289Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1574890,
    events_root: None,
}
2023-01-27T07:49:03.160295Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:03.160297Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mloadNonConst"::Berlin::0
2023-01-27T07:49:03.160299Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mloadNonConst.json"
2023-01-27T07:49:03.160301Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:03.160303Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:03.160393Z  INFO evm_eth_compliance::statetest::runner: UC : "mloadNonConst"
2023-01-27T07:49:03.160396Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1574890,
    events_root: None,
}
2023-01-27T07:49:03.160401Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:03.160403Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mloadNonConst"::Berlin::0
2023-01-27T07:49:03.160405Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mloadNonConst.json"
2023-01-27T07:49:03.160408Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:03.160409Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:03.160497Z  INFO evm_eth_compliance::statetest::runner: UC : "mloadNonConst"
2023-01-27T07:49:03.160501Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1574890,
    events_root: None,
}
2023-01-27T07:49:03.160505Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:03.160508Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mloadNonConst"::London::0
2023-01-27T07:49:03.160510Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mloadNonConst.json"
2023-01-27T07:49:03.160513Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:03.160514Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:03.160603Z  INFO evm_eth_compliance::statetest::runner: UC : "mloadNonConst"
2023-01-27T07:49:03.160607Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1574890,
    events_root: None,
}
2023-01-27T07:49:03.160612Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:03.160614Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mloadNonConst"::London::0
2023-01-27T07:49:03.160616Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mloadNonConst.json"
2023-01-27T07:49:03.160618Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:03.160619Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:03.160712Z  INFO evm_eth_compliance::statetest::runner: UC : "mloadNonConst"
2023-01-27T07:49:03.160715Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1574890,
    events_root: None,
}
2023-01-27T07:49:03.160720Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:03.160722Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mloadNonConst"::Merge::0
2023-01-27T07:49:03.160724Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mloadNonConst.json"
2023-01-27T07:49:03.160726Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:03.160727Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:03.160813Z  INFO evm_eth_compliance::statetest::runner: UC : "mloadNonConst"
2023-01-27T07:49:03.160817Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1574890,
    events_root: None,
}
2023-01-27T07:49:03.160822Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:03.160824Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mloadNonConst"::Merge::0
2023-01-27T07:49:03.160826Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mloadNonConst.json"
2023-01-27T07:49:03.160828Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:03.160830Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:03.160926Z  INFO evm_eth_compliance::statetest::runner: UC : "mloadNonConst"
2023-01-27T07:49:03.160932Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1574890,
    events_root: None,
}
2023-01-27T07:49:03.162805Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:354.332746ms
2023-01-27T07:49:03.445777Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/modNonConst.json", Total Files :: 1
2023-01-27T07:49:03.500245Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:49:03.500379Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:03.500382Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:49:03.500436Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:03.500508Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:03.500511Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "modNonConst"::Istanbul::0
2023-01-27T07:49:03.500514Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/modNonConst.json"
2023-01-27T07:49:03.500517Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:03.500519Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:03.859956Z  INFO evm_eth_compliance::statetest::runner: UC : "modNonConst"
2023-01-27T07:49:03.859971Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618752,
    events_root: None,
}
2023-01-27T07:49:03.859981Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:03.859985Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "modNonConst"::Istanbul::0
2023-01-27T07:49:03.859987Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/modNonConst.json"
2023-01-27T07:49:03.859990Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:03.859991Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:03.860107Z  INFO evm_eth_compliance::statetest::runner: UC : "modNonConst"
2023-01-27T07:49:03.860111Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618752,
    events_root: None,
}
2023-01-27T07:49:03.860116Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:03.860118Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "modNonConst"::Berlin::0
2023-01-27T07:49:03.860120Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/modNonConst.json"
2023-01-27T07:49:03.860124Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:03.860125Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:03.860215Z  INFO evm_eth_compliance::statetest::runner: UC : "modNonConst"
2023-01-27T07:49:03.860218Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618752,
    events_root: None,
}
2023-01-27T07:49:03.860223Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:03.860225Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "modNonConst"::Berlin::0
2023-01-27T07:49:03.860226Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/modNonConst.json"
2023-01-27T07:49:03.860229Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:03.860230Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:03.860318Z  INFO evm_eth_compliance::statetest::runner: UC : "modNonConst"
2023-01-27T07:49:03.860322Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618752,
    events_root: None,
}
2023-01-27T07:49:03.860327Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:03.860329Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "modNonConst"::London::0
2023-01-27T07:49:03.860331Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/modNonConst.json"
2023-01-27T07:49:03.860334Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:03.860336Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:03.860423Z  INFO evm_eth_compliance::statetest::runner: UC : "modNonConst"
2023-01-27T07:49:03.860427Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618752,
    events_root: None,
}
2023-01-27T07:49:03.860431Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:03.860433Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "modNonConst"::London::0
2023-01-27T07:49:03.860435Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/modNonConst.json"
2023-01-27T07:49:03.860437Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:03.860439Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:03.860526Z  INFO evm_eth_compliance::statetest::runner: UC : "modNonConst"
2023-01-27T07:49:03.860529Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618752,
    events_root: None,
}
2023-01-27T07:49:03.860534Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:03.860536Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "modNonConst"::Merge::0
2023-01-27T07:49:03.860538Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/modNonConst.json"
2023-01-27T07:49:03.860541Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:03.860543Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:03.860629Z  INFO evm_eth_compliance::statetest::runner: UC : "modNonConst"
2023-01-27T07:49:03.860633Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618752,
    events_root: None,
}
2023-01-27T07:49:03.860637Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:03.860639Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "modNonConst"::Merge::0
2023-01-27T07:49:03.860641Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/modNonConst.json"
2023-01-27T07:49:03.860645Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:03.860646Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:03.860733Z  INFO evm_eth_compliance::statetest::runner: UC : "modNonConst"
2023-01-27T07:49:03.860736Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618752,
    events_root: None,
}
2023-01-27T07:49:03.862279Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:360.500389ms
2023-01-27T07:49:04.149613Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mstore8NonConst.json", Total Files :: 1
2023-01-27T07:49:04.179088Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:49:04.179229Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:04.179232Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:49:04.179286Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:04.179360Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:04.179363Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mstore8NonConst"::Istanbul::0
2023-01-27T07:49:04.179366Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mstore8NonConst.json"
2023-01-27T07:49:04.179370Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:04.179371Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:04.522046Z  INFO evm_eth_compliance::statetest::runner: UC : "mstore8NonConst"
2023-01-27T07:49:04.522065Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1615549,
    events_root: None,
}
2023-01-27T07:49:04.522078Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:04.522082Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mstore8NonConst"::Istanbul::0
2023-01-27T07:49:04.522083Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mstore8NonConst.json"
2023-01-27T07:49:04.522086Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:04.522088Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:04.522222Z  INFO evm_eth_compliance::statetest::runner: UC : "mstore8NonConst"
2023-01-27T07:49:04.522226Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1615549,
    events_root: None,
}
2023-01-27T07:49:04.522233Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:04.522237Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mstore8NonConst"::Berlin::0
2023-01-27T07:49:04.522240Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mstore8NonConst.json"
2023-01-27T07:49:04.522242Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:04.522243Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:04.522341Z  INFO evm_eth_compliance::statetest::runner: UC : "mstore8NonConst"
2023-01-27T07:49:04.522345Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1615549,
    events_root: None,
}
2023-01-27T07:49:04.522350Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:04.522352Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mstore8NonConst"::Berlin::0
2023-01-27T07:49:04.522354Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mstore8NonConst.json"
2023-01-27T07:49:04.522356Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:04.522357Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:04.522452Z  INFO evm_eth_compliance::statetest::runner: UC : "mstore8NonConst"
2023-01-27T07:49:04.522456Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1615549,
    events_root: None,
}
2023-01-27T07:49:04.522461Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:04.522463Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mstore8NonConst"::London::0
2023-01-27T07:49:04.522465Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mstore8NonConst.json"
2023-01-27T07:49:04.522468Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:04.522469Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:04.522568Z  INFO evm_eth_compliance::statetest::runner: UC : "mstore8NonConst"
2023-01-27T07:49:04.522572Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1615549,
    events_root: None,
}
2023-01-27T07:49:04.522578Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:04.522580Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mstore8NonConst"::London::0
2023-01-27T07:49:04.522583Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mstore8NonConst.json"
2023-01-27T07:49:04.522587Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:04.522589Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:04.522695Z  INFO evm_eth_compliance::statetest::runner: UC : "mstore8NonConst"
2023-01-27T07:49:04.522699Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1615549,
    events_root: None,
}
2023-01-27T07:49:04.522704Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:04.522706Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mstore8NonConst"::Merge::0
2023-01-27T07:49:04.522708Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mstore8NonConst.json"
2023-01-27T07:49:04.522710Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:04.522711Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:04.522806Z  INFO evm_eth_compliance::statetest::runner: UC : "mstore8NonConst"
2023-01-27T07:49:04.522810Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1615549,
    events_root: None,
}
2023-01-27T07:49:04.522815Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:04.522817Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mstore8NonConst"::Merge::0
2023-01-27T07:49:04.522819Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mstore8NonConst.json"
2023-01-27T07:49:04.522821Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:04.522823Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:04.522916Z  INFO evm_eth_compliance::statetest::runner: UC : "mstore8NonConst"
2023-01-27T07:49:04.522920Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1615549,
    events_root: None,
}
2023-01-27T07:49:04.524466Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:343.841742ms
2023-01-27T07:49:04.817388Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mstoreNonConst.json", Total Files :: 1
2023-01-27T07:49:04.849162Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:49:04.849411Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:04.849418Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:49:04.849496Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:04.849606Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:04.849611Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mstoreNonConst"::Istanbul::0
2023-01-27T07:49:04.849615Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mstoreNonConst.json"
2023-01-27T07:49:04.849618Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:04.849619Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:05.230097Z  INFO evm_eth_compliance::statetest::runner: UC : "mstoreNonConst"
2023-01-27T07:49:05.230113Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1616645,
    events_root: None,
}
2023-01-27T07:49:05.230126Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:05.230132Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mstoreNonConst"::Istanbul::0
2023-01-27T07:49:05.230134Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mstoreNonConst.json"
2023-01-27T07:49:05.230138Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:05.230140Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:05.230319Z  INFO evm_eth_compliance::statetest::runner: UC : "mstoreNonConst"
2023-01-27T07:49:05.230338Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1616645,
    events_root: None,
}
2023-01-27T07:49:05.230354Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:05.230357Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mstoreNonConst"::Berlin::0
2023-01-27T07:49:05.230360Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mstoreNonConst.json"
2023-01-27T07:49:05.230363Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:05.230366Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:05.230481Z  INFO evm_eth_compliance::statetest::runner: UC : "mstoreNonConst"
2023-01-27T07:49:05.230486Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1616645,
    events_root: None,
}
2023-01-27T07:49:05.230491Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:05.230494Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mstoreNonConst"::Berlin::0
2023-01-27T07:49:05.230495Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mstoreNonConst.json"
2023-01-27T07:49:05.230498Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:05.230499Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:05.230602Z  INFO evm_eth_compliance::statetest::runner: UC : "mstoreNonConst"
2023-01-27T07:49:05.230605Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1616645,
    events_root: None,
}
2023-01-27T07:49:05.230611Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:05.230613Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mstoreNonConst"::London::0
2023-01-27T07:49:05.230614Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mstoreNonConst.json"
2023-01-27T07:49:05.230617Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:05.230618Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:05.230712Z  INFO evm_eth_compliance::statetest::runner: UC : "mstoreNonConst"
2023-01-27T07:49:05.230717Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1616645,
    events_root: None,
}
2023-01-27T07:49:05.230723Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:05.230724Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mstoreNonConst"::London::0
2023-01-27T07:49:05.230726Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mstoreNonConst.json"
2023-01-27T07:49:05.230729Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:05.230730Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:05.230824Z  INFO evm_eth_compliance::statetest::runner: UC : "mstoreNonConst"
2023-01-27T07:49:05.230829Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1616645,
    events_root: None,
}
2023-01-27T07:49:05.230835Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:05.230839Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mstoreNonConst"::Merge::0
2023-01-27T07:49:05.230842Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mstoreNonConst.json"
2023-01-27T07:49:05.230845Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:05.230847Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:05.230970Z  INFO evm_eth_compliance::statetest::runner: UC : "mstoreNonConst"
2023-01-27T07:49:05.230975Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1616645,
    events_root: None,
}
2023-01-27T07:49:05.230981Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:05.230984Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mstoreNonConst"::Merge::0
2023-01-27T07:49:05.230987Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mstoreNonConst.json"
2023-01-27T07:49:05.230990Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:05.230992Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:05.231119Z  INFO evm_eth_compliance::statetest::runner: UC : "mstoreNonConst"
2023-01-27T07:49:05.231124Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1616645,
    events_root: None,
}
2023-01-27T07:49:05.233025Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:381.973916ms
2023-01-27T07:49:05.521070Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mulNonConst.json", Total Files :: 1
2023-01-27T07:49:05.586449Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:49:05.586607Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:05.586613Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:49:05.586673Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:05.586757Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:05.586762Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulNonConst"::Istanbul::0
2023-01-27T07:49:05.586765Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mulNonConst.json"
2023-01-27T07:49:05.586769Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:05.586775Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:05.969405Z  INFO evm_eth_compliance::statetest::runner: UC : "mulNonConst"
2023-01-27T07:49:05.969420Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1621056,
    events_root: None,
}
2023-01-27T07:49:05.969431Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:05.969434Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulNonConst"::Istanbul::0
2023-01-27T07:49:05.969436Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mulNonConst.json"
2023-01-27T07:49:05.969439Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:05.969441Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:05.969559Z  INFO evm_eth_compliance::statetest::runner: UC : "mulNonConst"
2023-01-27T07:49:05.969563Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1621056,
    events_root: None,
}
2023-01-27T07:49:05.969568Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:05.969570Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulNonConst"::Berlin::0
2023-01-27T07:49:05.969572Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mulNonConst.json"
2023-01-27T07:49:05.969574Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:05.969575Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:05.969673Z  INFO evm_eth_compliance::statetest::runner: UC : "mulNonConst"
2023-01-27T07:49:05.969677Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1621056,
    events_root: None,
}
2023-01-27T07:49:05.969682Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:05.969684Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulNonConst"::Berlin::0
2023-01-27T07:49:05.969685Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mulNonConst.json"
2023-01-27T07:49:05.969688Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:05.969689Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:05.969784Z  INFO evm_eth_compliance::statetest::runner: UC : "mulNonConst"
2023-01-27T07:49:05.969789Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1621056,
    events_root: None,
}
2023-01-27T07:49:05.969794Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:05.969796Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulNonConst"::London::0
2023-01-27T07:49:05.969798Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mulNonConst.json"
2023-01-27T07:49:05.969800Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:05.969802Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:05.969896Z  INFO evm_eth_compliance::statetest::runner: UC : "mulNonConst"
2023-01-27T07:49:05.969899Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1621056,
    events_root: None,
}
2023-01-27T07:49:05.969904Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:05.969907Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulNonConst"::London::0
2023-01-27T07:49:05.969910Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mulNonConst.json"
2023-01-27T07:49:05.969912Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:05.969913Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:05.970012Z  INFO evm_eth_compliance::statetest::runner: UC : "mulNonConst"
2023-01-27T07:49:05.970016Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1621056,
    events_root: None,
}
2023-01-27T07:49:05.970021Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:05.970023Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulNonConst"::Merge::0
2023-01-27T07:49:05.970025Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mulNonConst.json"
2023-01-27T07:49:05.970028Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:05.970031Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:05.970142Z  INFO evm_eth_compliance::statetest::runner: UC : "mulNonConst"
2023-01-27T07:49:05.970148Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1621056,
    events_root: None,
}
2023-01-27T07:49:05.970156Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:05.970158Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulNonConst"::Merge::0
2023-01-27T07:49:05.970161Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mulNonConst.json"
2023-01-27T07:49:05.970164Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:05.970166Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:05.970291Z  INFO evm_eth_compliance::statetest::runner: UC : "mulNonConst"
2023-01-27T07:49:05.970309Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1621056,
    events_root: None,
}
2023-01-27T07:49:05.971977Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:383.878931ms
2023-01-27T07:49:06.241108Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mulmodNonConst.json", Total Files :: 1
2023-01-27T07:49:06.272793Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:49:06.272935Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:06.272940Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:49:06.273011Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:06.273105Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:06.273109Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmodNonConst"::Istanbul::0
2023-01-27T07:49:06.273113Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mulmodNonConst.json"
2023-01-27T07:49:06.273117Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:06.273119Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:06.661538Z  INFO evm_eth_compliance::statetest::runner: UC : "mulmodNonConst"
2023-01-27T07:49:06.661556Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1664627,
    events_root: None,
}
2023-01-27T07:49:06.661568Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:06.661573Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmodNonConst"::Istanbul::0
2023-01-27T07:49:06.661575Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mulmodNonConst.json"
2023-01-27T07:49:06.661579Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:06.661581Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:06.661731Z  INFO evm_eth_compliance::statetest::runner: UC : "mulmodNonConst"
2023-01-27T07:49:06.661735Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1664627,
    events_root: None,
}
2023-01-27T07:49:06.661741Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:06.661743Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmodNonConst"::Berlin::0
2023-01-27T07:49:06.661745Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mulmodNonConst.json"
2023-01-27T07:49:06.661748Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:06.661750Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:06.661850Z  INFO evm_eth_compliance::statetest::runner: UC : "mulmodNonConst"
2023-01-27T07:49:06.661854Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1664627,
    events_root: None,
}
2023-01-27T07:49:06.661859Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:06.661862Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmodNonConst"::Berlin::0
2023-01-27T07:49:06.661863Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mulmodNonConst.json"
2023-01-27T07:49:06.661866Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:06.661867Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:06.661967Z  INFO evm_eth_compliance::statetest::runner: UC : "mulmodNonConst"
2023-01-27T07:49:06.661970Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1664627,
    events_root: None,
}
2023-01-27T07:49:06.661975Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:06.661978Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmodNonConst"::London::0
2023-01-27T07:49:06.661980Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mulmodNonConst.json"
2023-01-27T07:49:06.661982Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:06.661984Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:06.662080Z  INFO evm_eth_compliance::statetest::runner: UC : "mulmodNonConst"
2023-01-27T07:49:06.662084Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1664627,
    events_root: None,
}
2023-01-27T07:49:06.662090Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:06.662092Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmodNonConst"::London::0
2023-01-27T07:49:06.662094Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mulmodNonConst.json"
2023-01-27T07:49:06.662096Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:06.662098Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:06.662221Z  INFO evm_eth_compliance::statetest::runner: UC : "mulmodNonConst"
2023-01-27T07:49:06.662227Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1664627,
    events_root: None,
}
2023-01-27T07:49:06.662233Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:06.662236Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmodNonConst"::Merge::0
2023-01-27T07:49:06.662238Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mulmodNonConst.json"
2023-01-27T07:49:06.662242Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:06.662244Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:06.662377Z  INFO evm_eth_compliance::statetest::runner: UC : "mulmodNonConst"
2023-01-27T07:49:06.662382Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1664627,
    events_root: None,
}
2023-01-27T07:49:06.662387Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:06.662391Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "mulmodNonConst"::Merge::0
2023-01-27T07:49:06.662393Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/mulmodNonConst.json"
2023-01-27T07:49:06.662395Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:06.662397Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:06.662514Z  INFO evm_eth_compliance::statetest::runner: UC : "mulmodNonConst"
2023-01-27T07:49:06.662519Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1664627,
    events_root: None,
}
2023-01-27T07:49:06.664524Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:389.737605ms
2023-01-27T07:49:06.941446Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/notNonConst.json", Total Files :: 1
2023-01-27T07:49:06.993947Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:49:06.994083Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:06.994087Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:49:06.994140Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:06.994211Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:06.994214Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "notNonConst"::Istanbul::0
2023-01-27T07:49:06.994217Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/notNonConst.json"
2023-01-27T07:49:06.994220Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:06.994221Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:07.357692Z  INFO evm_eth_compliance::statetest::runner: UC : "notNonConst"
2023-01-27T07:49:07.357709Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2545893,
    events_root: None,
}
2023-01-27T07:49:07.357723Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:07.357728Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "notNonConst"::Istanbul::0
2023-01-27T07:49:07.357730Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/notNonConst.json"
2023-01-27T07:49:07.357735Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:07.357737Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:07.357890Z  INFO evm_eth_compliance::statetest::runner: UC : "notNonConst"
2023-01-27T07:49:07.357895Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1602938,
    events_root: None,
}
2023-01-27T07:49:07.357901Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:07.357903Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "notNonConst"::Berlin::0
2023-01-27T07:49:07.357904Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/notNonConst.json"
2023-01-27T07:49:07.357907Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:07.357908Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:07.358009Z  INFO evm_eth_compliance::statetest::runner: UC : "notNonConst"
2023-01-27T07:49:07.358013Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1602938,
    events_root: None,
}
2023-01-27T07:49:07.358018Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:07.358020Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "notNonConst"::Berlin::0
2023-01-27T07:49:07.358022Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/notNonConst.json"
2023-01-27T07:49:07.358025Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:07.358026Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:07.358124Z  INFO evm_eth_compliance::statetest::runner: UC : "notNonConst"
2023-01-27T07:49:07.358128Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1602938,
    events_root: None,
}
2023-01-27T07:49:07.358133Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:07.358135Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "notNonConst"::London::0
2023-01-27T07:49:07.358136Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/notNonConst.json"
2023-01-27T07:49:07.358139Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:07.358140Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:07.358238Z  INFO evm_eth_compliance::statetest::runner: UC : "notNonConst"
2023-01-27T07:49:07.358242Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1602938,
    events_root: None,
}
2023-01-27T07:49:07.358247Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:07.358248Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "notNonConst"::London::0
2023-01-27T07:49:07.358250Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/notNonConst.json"
2023-01-27T07:49:07.358253Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:07.358254Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:07.358351Z  INFO evm_eth_compliance::statetest::runner: UC : "notNonConst"
2023-01-27T07:49:07.358356Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1602938,
    events_root: None,
}
2023-01-27T07:49:07.358361Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:07.358363Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "notNonConst"::Merge::0
2023-01-27T07:49:07.358365Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/notNonConst.json"
2023-01-27T07:49:07.358367Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:07.358369Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:07.358480Z  INFO evm_eth_compliance::statetest::runner: UC : "notNonConst"
2023-01-27T07:49:07.358484Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1602938,
    events_root: None,
}
2023-01-27T07:49:07.358489Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:07.358491Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "notNonConst"::Merge::0
2023-01-27T07:49:07.358493Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/notNonConst.json"
2023-01-27T07:49:07.358495Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:07.358497Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:07.358594Z  INFO evm_eth_compliance::statetest::runner: UC : "notNonConst"
2023-01-27T07:49:07.358598Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1602938,
    events_root: None,
}
2023-01-27T07:49:07.360409Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:364.662356ms
2023-01-27T07:49:07.624437Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/orNonConst.json", Total Files :: 1
2023-01-27T07:49:07.654962Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:49:07.655100Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:07.655104Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:49:07.655159Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:07.655229Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:07.655232Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "orNonConst"::Istanbul::0
2023-01-27T07:49:07.655235Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/orNonConst.json"
2023-01-27T07:49:07.655238Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:07.655240Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:08.007454Z  INFO evm_eth_compliance::statetest::runner: UC : "orNonConst"
2023-01-27T07:49:08.007469Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618736,
    events_root: None,
}
2023-01-27T07:49:08.007480Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:08.007487Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "orNonConst"::Istanbul::0
2023-01-27T07:49:08.007489Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/orNonConst.json"
2023-01-27T07:49:08.007492Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:08.007494Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:08.007625Z  INFO evm_eth_compliance::statetest::runner: UC : "orNonConst"
2023-01-27T07:49:08.007629Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618736,
    events_root: None,
}
2023-01-27T07:49:08.007636Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:08.007639Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "orNonConst"::Berlin::0
2023-01-27T07:49:08.007641Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/orNonConst.json"
2023-01-27T07:49:08.007645Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:08.007647Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:08.007752Z  INFO evm_eth_compliance::statetest::runner: UC : "orNonConst"
2023-01-27T07:49:08.007757Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618736,
    events_root: None,
}
2023-01-27T07:49:08.007763Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:08.007766Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "orNonConst"::Berlin::0
2023-01-27T07:49:08.007769Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/orNonConst.json"
2023-01-27T07:49:08.007772Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:08.007774Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:08.007880Z  INFO evm_eth_compliance::statetest::runner: UC : "orNonConst"
2023-01-27T07:49:08.007885Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618736,
    events_root: None,
}
2023-01-27T07:49:08.007891Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:08.007894Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "orNonConst"::London::0
2023-01-27T07:49:08.007896Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/orNonConst.json"
2023-01-27T07:49:08.007899Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:08.007902Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:08.008003Z  INFO evm_eth_compliance::statetest::runner: UC : "orNonConst"
2023-01-27T07:49:08.008007Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618736,
    events_root: None,
}
2023-01-27T07:49:08.008013Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:08.008016Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "orNonConst"::London::0
2023-01-27T07:49:08.008019Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/orNonConst.json"
2023-01-27T07:49:08.008022Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:08.008024Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:08.008125Z  INFO evm_eth_compliance::statetest::runner: UC : "orNonConst"
2023-01-27T07:49:08.008129Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618736,
    events_root: None,
}
2023-01-27T07:49:08.008135Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:08.008138Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "orNonConst"::Merge::0
2023-01-27T07:49:08.008141Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/orNonConst.json"
2023-01-27T07:49:08.008144Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:08.008146Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:08.008247Z  INFO evm_eth_compliance::statetest::runner: UC : "orNonConst"
2023-01-27T07:49:08.008252Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618736,
    events_root: None,
}
2023-01-27T07:49:08.008258Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:08.008261Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "orNonConst"::Merge::0
2023-01-27T07:49:08.008263Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/orNonConst.json"
2023-01-27T07:49:08.008266Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:08.008269Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:08.008368Z  INFO evm_eth_compliance::statetest::runner: UC : "orNonConst"
2023-01-27T07:49:08.008373Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618736,
    events_root: None,
}
2023-01-27T07:49:08.009959Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:353.422491ms
2023-01-27T07:49:08.280830Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/returnNonConst.json", Total Files :: 1
2023-01-27T07:49:08.312563Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:49:08.312710Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:08.312715Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:49:08.312788Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:08.312874Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:08.312878Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returnNonConst"::Istanbul::0
2023-01-27T07:49:08.312881Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/returnNonConst.json"
2023-01-27T07:49:08.312884Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:08.312886Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:08.673390Z  INFO evm_eth_compliance::statetest::runner: UC : "returnNonConst"
2023-01-27T07:49:08.673410Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1615897,
    events_root: None,
}
2023-01-27T07:49:08.673424Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:08.673428Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returnNonConst"::Istanbul::0
2023-01-27T07:49:08.673431Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/returnNonConst.json"
2023-01-27T07:49:08.673435Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:08.673437Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:08.673600Z  INFO evm_eth_compliance::statetest::runner: UC : "returnNonConst"
2023-01-27T07:49:08.673605Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1615897,
    events_root: None,
}
2023-01-27T07:49:08.673611Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:08.673614Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returnNonConst"::Berlin::0
2023-01-27T07:49:08.673615Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/returnNonConst.json"
2023-01-27T07:49:08.673618Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:08.673619Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:08.673736Z  INFO evm_eth_compliance::statetest::runner: UC : "returnNonConst"
2023-01-27T07:49:08.673740Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1615897,
    events_root: None,
}
2023-01-27T07:49:08.673746Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:08.673748Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returnNonConst"::Berlin::0
2023-01-27T07:49:08.673751Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/returnNonConst.json"
2023-01-27T07:49:08.673753Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:08.673754Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:08.673849Z  INFO evm_eth_compliance::statetest::runner: UC : "returnNonConst"
2023-01-27T07:49:08.673854Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1615897,
    events_root: None,
}
2023-01-27T07:49:08.673859Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:08.673861Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returnNonConst"::London::0
2023-01-27T07:49:08.673863Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/returnNonConst.json"
2023-01-27T07:49:08.673865Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:08.673870Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:08.673961Z  INFO evm_eth_compliance::statetest::runner: UC : "returnNonConst"
2023-01-27T07:49:08.673965Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1615897,
    events_root: None,
}
2023-01-27T07:49:08.673970Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:08.673972Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returnNonConst"::London::0
2023-01-27T07:49:08.673974Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/returnNonConst.json"
2023-01-27T07:49:08.673976Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:08.673978Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:08.674095Z  INFO evm_eth_compliance::statetest::runner: UC : "returnNonConst"
2023-01-27T07:49:08.674100Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1615897,
    events_root: None,
}
2023-01-27T07:49:08.674106Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:08.674108Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returnNonConst"::Merge::0
2023-01-27T07:49:08.674109Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/returnNonConst.json"
2023-01-27T07:49:08.674114Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:08.674116Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:08.674217Z  INFO evm_eth_compliance::statetest::runner: UC : "returnNonConst"
2023-01-27T07:49:08.674221Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1615897,
    events_root: None,
}
2023-01-27T07:49:08.674226Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:08.674228Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "returnNonConst"::Merge::0
2023-01-27T07:49:08.674229Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/returnNonConst.json"
2023-01-27T07:49:08.674233Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:08.674234Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:08.674326Z  INFO evm_eth_compliance::statetest::runner: UC : "returnNonConst"
2023-01-27T07:49:08.674330Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1615897,
    events_root: None,
}
2023-01-27T07:49:08.676120Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:361.776759ms
2023-01-27T07:49:08.954097Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sdivNonConst.json", Total Files :: 1
2023-01-27T07:49:08.985532Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:49:08.985685Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:08.985690Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:49:08.985762Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:08.985846Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:08.985850Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdivNonConst"::Istanbul::0
2023-01-27T07:49:08.985852Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sdivNonConst.json"
2023-01-27T07:49:08.985856Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:08.985857Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:09.374067Z  INFO evm_eth_compliance::statetest::runner: UC : "sdivNonConst"
2023-01-27T07:49:09.374081Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618820,
    events_root: None,
}
2023-01-27T07:49:09.374094Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:09.374099Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdivNonConst"::Istanbul::0
2023-01-27T07:49:09.374102Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sdivNonConst.json"
2023-01-27T07:49:09.374106Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:09.374107Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:09.374223Z  INFO evm_eth_compliance::statetest::runner: UC : "sdivNonConst"
2023-01-27T07:49:09.374228Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618820,
    events_root: None,
}
2023-01-27T07:49:09.374235Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:09.374240Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdivNonConst"::Berlin::0
2023-01-27T07:49:09.374243Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sdivNonConst.json"
2023-01-27T07:49:09.374247Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:09.374248Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:09.374351Z  INFO evm_eth_compliance::statetest::runner: UC : "sdivNonConst"
2023-01-27T07:49:09.374355Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618820,
    events_root: None,
}
2023-01-27T07:49:09.374361Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:09.374364Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdivNonConst"::Berlin::0
2023-01-27T07:49:09.374368Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sdivNonConst.json"
2023-01-27T07:49:09.374372Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:09.374374Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:09.374475Z  INFO evm_eth_compliance::statetest::runner: UC : "sdivNonConst"
2023-01-27T07:49:09.374479Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618820,
    events_root: None,
}
2023-01-27T07:49:09.374485Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:09.374488Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdivNonConst"::London::0
2023-01-27T07:49:09.374491Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sdivNonConst.json"
2023-01-27T07:49:09.374494Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:09.374496Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:09.374597Z  INFO evm_eth_compliance::statetest::runner: UC : "sdivNonConst"
2023-01-27T07:49:09.374601Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618820,
    events_root: None,
}
2023-01-27T07:49:09.374607Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:09.374610Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdivNonConst"::London::0
2023-01-27T07:49:09.374613Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sdivNonConst.json"
2023-01-27T07:49:09.374616Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:09.374618Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:09.374717Z  INFO evm_eth_compliance::statetest::runner: UC : "sdivNonConst"
2023-01-27T07:49:09.374722Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618820,
    events_root: None,
}
2023-01-27T07:49:09.374728Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:09.374731Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdivNonConst"::Merge::0
2023-01-27T07:49:09.374733Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sdivNonConst.json"
2023-01-27T07:49:09.374736Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:09.374739Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:09.374849Z  INFO evm_eth_compliance::statetest::runner: UC : "sdivNonConst"
2023-01-27T07:49:09.374855Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618820,
    events_root: None,
}
2023-01-27T07:49:09.374861Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:09.374863Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sdivNonConst"::Merge::0
2023-01-27T07:49:09.374865Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sdivNonConst.json"
2023-01-27T07:49:09.374868Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:09.374870Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:09.374989Z  INFO evm_eth_compliance::statetest::runner: UC : "sdivNonConst"
2023-01-27T07:49:09.374995Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618820,
    events_root: None,
}
2023-01-27T07:49:09.377408Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:389.474233ms
2023-01-27T07:49:09.650674Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sgtNonConst.json", Total Files :: 1
2023-01-27T07:49:09.714654Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:49:09.714796Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:09.714800Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:49:09.714856Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:09.714930Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:09.714935Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sgtNonConst"::Istanbul::0
2023-01-27T07:49:09.714938Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sgtNonConst.json"
2023-01-27T07:49:09.714941Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:09.714942Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:10.113359Z  INFO evm_eth_compliance::statetest::runner: UC : "sgtNonConst"
2023-01-27T07:49:10.113380Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618952,
    events_root: None,
}
2023-01-27T07:49:10.113395Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:10.113401Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sgtNonConst"::Istanbul::0
2023-01-27T07:49:10.113403Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sgtNonConst.json"
2023-01-27T07:49:10.113407Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:10.113409Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:10.113558Z  INFO evm_eth_compliance::statetest::runner: UC : "sgtNonConst"
2023-01-27T07:49:10.113564Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618952,
    events_root: None,
}
2023-01-27T07:49:10.113572Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:10.113575Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sgtNonConst"::Berlin::0
2023-01-27T07:49:10.113579Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sgtNonConst.json"
2023-01-27T07:49:10.113583Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:10.113585Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:10.113717Z  INFO evm_eth_compliance::statetest::runner: UC : "sgtNonConst"
2023-01-27T07:49:10.113722Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618952,
    events_root: None,
}
2023-01-27T07:49:10.113727Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:10.113729Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sgtNonConst"::Berlin::0
2023-01-27T07:49:10.113732Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sgtNonConst.json"
2023-01-27T07:49:10.113735Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:10.113738Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:10.113860Z  INFO evm_eth_compliance::statetest::runner: UC : "sgtNonConst"
2023-01-27T07:49:10.113865Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618952,
    events_root: None,
}
2023-01-27T07:49:10.113871Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:10.113874Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sgtNonConst"::London::0
2023-01-27T07:49:10.113877Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sgtNonConst.json"
2023-01-27T07:49:10.113880Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:10.113882Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:10.114005Z  INFO evm_eth_compliance::statetest::runner: UC : "sgtNonConst"
2023-01-27T07:49:10.114011Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618952,
    events_root: None,
}
2023-01-27T07:49:10.114018Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:10.114021Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sgtNonConst"::London::0
2023-01-27T07:49:10.114023Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sgtNonConst.json"
2023-01-27T07:49:10.114027Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:10.114029Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:10.114134Z  INFO evm_eth_compliance::statetest::runner: UC : "sgtNonConst"
2023-01-27T07:49:10.114139Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618952,
    events_root: None,
}
2023-01-27T07:49:10.114144Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:10.114146Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sgtNonConst"::Merge::0
2023-01-27T07:49:10.114148Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sgtNonConst.json"
2023-01-27T07:49:10.114150Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:10.114152Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:10.114251Z  INFO evm_eth_compliance::statetest::runner: UC : "sgtNonConst"
2023-01-27T07:49:10.114255Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618952,
    events_root: None,
}
2023-01-27T07:49:10.114259Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:10.114262Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sgtNonConst"::Merge::0
2023-01-27T07:49:10.114263Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sgtNonConst.json"
2023-01-27T07:49:10.114266Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:10.114267Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:10.114358Z  INFO evm_eth_compliance::statetest::runner: UC : "sgtNonConst"
2023-01-27T07:49:10.114362Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618952,
    events_root: None,
}
2023-01-27T07:49:10.115879Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:399.717973ms
2023-01-27T07:49:10.379435Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sha3NonConst.json", Total Files :: 1
2023-01-27T07:49:10.443418Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:49:10.443561Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:10.443566Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:49:10.443620Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:10.443692Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:10.443694Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3NonConst"::Istanbul::0
2023-01-27T07:49:10.443697Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sha3NonConst.json"
2023-01-27T07:49:10.443700Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:10.443702Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:10.825821Z  INFO evm_eth_compliance::statetest::runner: UC : "sha3NonConst"
2023-01-27T07:49:10.825839Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2607761,
    events_root: None,
}
2023-01-27T07:49:10.825850Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:10.825854Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3NonConst"::Istanbul::0
2023-01-27T07:49:10.825855Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sha3NonConst.json"
2023-01-27T07:49:10.825858Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:10.825860Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:10.825987Z  INFO evm_eth_compliance::statetest::runner: UC : "sha3NonConst"
2023-01-27T07:49:10.825991Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1666066,
    events_root: None,
}
2023-01-27T07:49:10.825997Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:10.825999Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3NonConst"::Berlin::0
2023-01-27T07:49:10.826000Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sha3NonConst.json"
2023-01-27T07:49:10.826003Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:10.826004Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:10.826107Z  INFO evm_eth_compliance::statetest::runner: UC : "sha3NonConst"
2023-01-27T07:49:10.826112Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1666066,
    events_root: None,
}
2023-01-27T07:49:10.826117Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:10.826119Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3NonConst"::Berlin::0
2023-01-27T07:49:10.826121Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sha3NonConst.json"
2023-01-27T07:49:10.826123Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:10.826125Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:10.826230Z  INFO evm_eth_compliance::statetest::runner: UC : "sha3NonConst"
2023-01-27T07:49:10.826234Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1666066,
    events_root: None,
}
2023-01-27T07:49:10.826239Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:10.826241Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3NonConst"::London::0
2023-01-27T07:49:10.826243Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sha3NonConst.json"
2023-01-27T07:49:10.826246Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:10.826248Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:10.826381Z  INFO evm_eth_compliance::statetest::runner: UC : "sha3NonConst"
2023-01-27T07:49:10.826387Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1666066,
    events_root: None,
}
2023-01-27T07:49:10.826394Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:10.826397Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3NonConst"::London::0
2023-01-27T07:49:10.826399Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sha3NonConst.json"
2023-01-27T07:49:10.826403Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:10.826405Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:10.826535Z  INFO evm_eth_compliance::statetest::runner: UC : "sha3NonConst"
2023-01-27T07:49:10.826540Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1666066,
    events_root: None,
}
2023-01-27T07:49:10.826545Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:10.826547Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3NonConst"::Merge::0
2023-01-27T07:49:10.826549Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sha3NonConst.json"
2023-01-27T07:49:10.826552Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:10.826553Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:10.826656Z  INFO evm_eth_compliance::statetest::runner: UC : "sha3NonConst"
2023-01-27T07:49:10.826660Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1666066,
    events_root: None,
}
2023-01-27T07:49:10.826665Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:10.826667Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sha3NonConst"::Merge::0
2023-01-27T07:49:10.826669Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sha3NonConst.json"
2023-01-27T07:49:10.826671Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:10.826673Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:10.826773Z  INFO evm_eth_compliance::statetest::runner: UC : "sha3NonConst"
2023-01-27T07:49:10.826776Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1666066,
    events_root: None,
}
2023-01-27T07:49:10.828467Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:383.368564ms
2023-01-27T07:49:11.103560Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/signextNonConst.json", Total Files :: 1
2023-01-27T07:49:11.165815Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:49:11.165947Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:11.165951Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:49:11.166004Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:11.166074Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:11.166076Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextNonConst"::Istanbul::0
2023-01-27T07:49:11.166079Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/signextNonConst.json"
2023-01-27T07:49:11.166083Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:11.166084Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:11.532432Z  INFO evm_eth_compliance::statetest::runner: UC : "signextNonConst"
2023-01-27T07:49:11.532449Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1619544,
    events_root: None,
}
2023-01-27T07:49:11.532460Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:11.532464Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextNonConst"::Istanbul::0
2023-01-27T07:49:11.532467Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/signextNonConst.json"
2023-01-27T07:49:11.532470Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:11.532471Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:11.532605Z  INFO evm_eth_compliance::statetest::runner: UC : "signextNonConst"
2023-01-27T07:49:11.532609Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1619544,
    events_root: None,
}
2023-01-27T07:49:11.532615Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:11.532617Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextNonConst"::Berlin::0
2023-01-27T07:49:11.532619Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/signextNonConst.json"
2023-01-27T07:49:11.532621Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:11.532623Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:11.532719Z  INFO evm_eth_compliance::statetest::runner: UC : "signextNonConst"
2023-01-27T07:49:11.532723Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1619544,
    events_root: None,
}
2023-01-27T07:49:11.532729Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:11.532731Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextNonConst"::Berlin::0
2023-01-27T07:49:11.532733Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/signextNonConst.json"
2023-01-27T07:49:11.532735Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:11.532737Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:11.532832Z  INFO evm_eth_compliance::statetest::runner: UC : "signextNonConst"
2023-01-27T07:49:11.532836Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1619544,
    events_root: None,
}
2023-01-27T07:49:11.532841Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:11.532843Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextNonConst"::London::0
2023-01-27T07:49:11.532844Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/signextNonConst.json"
2023-01-27T07:49:11.532848Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:11.532849Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:11.532942Z  INFO evm_eth_compliance::statetest::runner: UC : "signextNonConst"
2023-01-27T07:49:11.532946Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1619544,
    events_root: None,
}
2023-01-27T07:49:11.532950Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:11.532954Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextNonConst"::London::0
2023-01-27T07:49:11.532955Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/signextNonConst.json"
2023-01-27T07:49:11.532958Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:11.532959Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:11.533051Z  INFO evm_eth_compliance::statetest::runner: UC : "signextNonConst"
2023-01-27T07:49:11.533054Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1619544,
    events_root: None,
}
2023-01-27T07:49:11.533059Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:11.533062Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextNonConst"::Merge::0
2023-01-27T07:49:11.533064Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/signextNonConst.json"
2023-01-27T07:49:11.533066Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:11.533068Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:11.533160Z  INFO evm_eth_compliance::statetest::runner: UC : "signextNonConst"
2023-01-27T07:49:11.533164Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1619544,
    events_root: None,
}
2023-01-27T07:49:11.533169Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:11.533171Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "signextNonConst"::Merge::0
2023-01-27T07:49:11.533173Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/signextNonConst.json"
2023-01-27T07:49:11.533175Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:11.533177Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:11.533268Z  INFO evm_eth_compliance::statetest::runner: UC : "signextNonConst"
2023-01-27T07:49:11.533272Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1619544,
    events_root: None,
}
2023-01-27T07:49:11.534941Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:367.468101ms
2023-01-27T07:49:11.802681Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sloadNonConst.json", Total Files :: 1
2023-01-27T07:49:11.840237Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:49:11.840376Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:11.840381Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:49:11.840435Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:11.840509Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:11.840511Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sloadNonConst"::Istanbul::0
2023-01-27T07:49:11.840514Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sloadNonConst.json"
2023-01-27T07:49:11.840517Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:11.840518Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:12.237990Z  INFO evm_eth_compliance::statetest::runner: UC : "sloadNonConst"
2023-01-27T07:49:12.238006Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1575385,
    events_root: None,
}
2023-01-27T07:49:12.238017Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:12.238022Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sloadNonConst"::Istanbul::0
2023-01-27T07:49:12.238024Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sloadNonConst.json"
2023-01-27T07:49:12.238027Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:12.238028Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:12.238164Z  INFO evm_eth_compliance::statetest::runner: UC : "sloadNonConst"
2023-01-27T07:49:12.238168Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1575385,
    events_root: None,
}
2023-01-27T07:49:12.238174Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:12.238176Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sloadNonConst"::Berlin::0
2023-01-27T07:49:12.238179Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sloadNonConst.json"
2023-01-27T07:49:12.238181Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:12.238183Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:12.238279Z  INFO evm_eth_compliance::statetest::runner: UC : "sloadNonConst"
2023-01-27T07:49:12.238283Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1575385,
    events_root: None,
}
2023-01-27T07:49:12.238288Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:12.238292Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sloadNonConst"::Berlin::0
2023-01-27T07:49:12.238294Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sloadNonConst.json"
2023-01-27T07:49:12.238297Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:12.238298Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:12.238394Z  INFO evm_eth_compliance::statetest::runner: UC : "sloadNonConst"
2023-01-27T07:49:12.238398Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1575385,
    events_root: None,
}
2023-01-27T07:49:12.238403Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:12.238406Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sloadNonConst"::London::0
2023-01-27T07:49:12.238407Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sloadNonConst.json"
2023-01-27T07:49:12.238410Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:12.238411Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:12.238504Z  INFO evm_eth_compliance::statetest::runner: UC : "sloadNonConst"
2023-01-27T07:49:12.238508Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1575385,
    events_root: None,
}
2023-01-27T07:49:12.238512Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:12.238514Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sloadNonConst"::London::0
2023-01-27T07:49:12.238516Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sloadNonConst.json"
2023-01-27T07:49:12.238518Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:12.238520Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:12.238612Z  INFO evm_eth_compliance::statetest::runner: UC : "sloadNonConst"
2023-01-27T07:49:12.238616Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1575385,
    events_root: None,
}
2023-01-27T07:49:12.238620Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:12.238622Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sloadNonConst"::Merge::0
2023-01-27T07:49:12.238624Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sloadNonConst.json"
2023-01-27T07:49:12.238627Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:12.238628Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:12.238719Z  INFO evm_eth_compliance::statetest::runner: UC : "sloadNonConst"
2023-01-27T07:49:12.238723Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1575385,
    events_root: None,
}
2023-01-27T07:49:12.238729Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:12.238731Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sloadNonConst"::Merge::0
2023-01-27T07:49:12.238733Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sloadNonConst.json"
2023-01-27T07:49:12.238735Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:12.238737Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:12.238828Z  INFO evm_eth_compliance::statetest::runner: UC : "sloadNonConst"
2023-01-27T07:49:12.238832Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1575385,
    events_root: None,
}
2023-01-27T07:49:12.240526Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:398.60512ms
2023-01-27T07:49:12.525718Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sltNonConst.json", Total Files :: 1
2023-01-27T07:49:12.578347Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:49:12.578488Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:12.578492Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:49:12.578547Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:12.578619Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:12.578622Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sltNonConst"::Istanbul::0
2023-01-27T07:49:12.578625Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sltNonConst.json"
2023-01-27T07:49:12.578628Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:12.578630Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:12.933887Z  INFO evm_eth_compliance::statetest::runner: UC : "sltNonConst"
2023-01-27T07:49:12.933902Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618952,
    events_root: None,
}
2023-01-27T07:49:12.933914Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:12.933919Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sltNonConst"::Istanbul::0
2023-01-27T07:49:12.933921Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sltNonConst.json"
2023-01-27T07:49:12.933924Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:12.933926Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:12.934047Z  INFO evm_eth_compliance::statetest::runner: UC : "sltNonConst"
2023-01-27T07:49:12.934052Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618952,
    events_root: None,
}
2023-01-27T07:49:12.934059Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:12.934061Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sltNonConst"::Berlin::0
2023-01-27T07:49:12.934064Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sltNonConst.json"
2023-01-27T07:49:12.934068Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:12.934070Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:12.934170Z  INFO evm_eth_compliance::statetest::runner: UC : "sltNonConst"
2023-01-27T07:49:12.934174Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618952,
    events_root: None,
}
2023-01-27T07:49:12.934181Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:12.934183Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sltNonConst"::Berlin::0
2023-01-27T07:49:12.934186Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sltNonConst.json"
2023-01-27T07:49:12.934189Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:12.934192Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:12.934295Z  INFO evm_eth_compliance::statetest::runner: UC : "sltNonConst"
2023-01-27T07:49:12.934299Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618952,
    events_root: None,
}
2023-01-27T07:49:12.934305Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:12.934308Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sltNonConst"::London::0
2023-01-27T07:49:12.934310Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sltNonConst.json"
2023-01-27T07:49:12.934314Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:12.934316Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:12.934414Z  INFO evm_eth_compliance::statetest::runner: UC : "sltNonConst"
2023-01-27T07:49:12.934419Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618952,
    events_root: None,
}
2023-01-27T07:49:12.934425Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:12.934428Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sltNonConst"::London::0
2023-01-27T07:49:12.934430Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sltNonConst.json"
2023-01-27T07:49:12.934433Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:12.934436Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:12.934532Z  INFO evm_eth_compliance::statetest::runner: UC : "sltNonConst"
2023-01-27T07:49:12.934536Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618952,
    events_root: None,
}
2023-01-27T07:49:12.934542Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:12.934547Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sltNonConst"::Merge::0
2023-01-27T07:49:12.934550Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sltNonConst.json"
2023-01-27T07:49:12.934554Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:12.934556Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:12.934664Z  INFO evm_eth_compliance::statetest::runner: UC : "sltNonConst"
2023-01-27T07:49:12.934669Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618952,
    events_root: None,
}
2023-01-27T07:49:12.934676Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:12.934679Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sltNonConst"::Merge::0
2023-01-27T07:49:12.934681Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sltNonConst.json"
2023-01-27T07:49:12.934684Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:12.934686Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:12.934804Z  INFO evm_eth_compliance::statetest::runner: UC : "sltNonConst"
2023-01-27T07:49:12.934809Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618952,
    events_root: None,
}
2023-01-27T07:49:12.936474Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:356.471588ms
2023-01-27T07:49:13.221489Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/smodNonConst.json", Total Files :: 1
2023-01-27T07:49:13.268010Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:49:13.268152Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:13.268156Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:49:13.268209Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:13.268282Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:13.268284Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "smodNonConst"::Istanbul::0
2023-01-27T07:49:13.268287Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/smodNonConst.json"
2023-01-27T07:49:13.268290Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:13.268292Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:13.642547Z  INFO evm_eth_compliance::statetest::runner: UC : "smodNonConst"
2023-01-27T07:49:13.642562Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618820,
    events_root: None,
}
2023-01-27T07:49:13.642574Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:13.642577Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "smodNonConst"::Istanbul::0
2023-01-27T07:49:13.642579Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/smodNonConst.json"
2023-01-27T07:49:13.642582Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:13.642583Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:13.642716Z  INFO evm_eth_compliance::statetest::runner: UC : "smodNonConst"
2023-01-27T07:49:13.642720Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618820,
    events_root: None,
}
2023-01-27T07:49:13.642726Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:13.642729Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "smodNonConst"::Berlin::0
2023-01-27T07:49:13.642730Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/smodNonConst.json"
2023-01-27T07:49:13.642733Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:13.642734Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:13.642828Z  INFO evm_eth_compliance::statetest::runner: UC : "smodNonConst"
2023-01-27T07:49:13.642832Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618820,
    events_root: None,
}
2023-01-27T07:49:13.642837Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:13.642839Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "smodNonConst"::Berlin::0
2023-01-27T07:49:13.642841Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/smodNonConst.json"
2023-01-27T07:49:13.642843Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:13.642845Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:13.642939Z  INFO evm_eth_compliance::statetest::runner: UC : "smodNonConst"
2023-01-27T07:49:13.642942Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618820,
    events_root: None,
}
2023-01-27T07:49:13.642947Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:13.642950Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "smodNonConst"::London::0
2023-01-27T07:49:13.642951Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/smodNonConst.json"
2023-01-27T07:49:13.642954Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:13.642955Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:13.643048Z  INFO evm_eth_compliance::statetest::runner: UC : "smodNonConst"
2023-01-27T07:49:13.643052Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618820,
    events_root: None,
}
2023-01-27T07:49:13.643057Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:13.643059Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "smodNonConst"::London::0
2023-01-27T07:49:13.643061Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/smodNonConst.json"
2023-01-27T07:49:13.643064Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:13.643066Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:13.643187Z  INFO evm_eth_compliance::statetest::runner: UC : "smodNonConst"
2023-01-27T07:49:13.643193Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618820,
    events_root: None,
}
2023-01-27T07:49:13.643200Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:13.643202Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "smodNonConst"::Merge::0
2023-01-27T07:49:13.643205Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/smodNonConst.json"
2023-01-27T07:49:13.643208Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:13.643210Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:13.643335Z  INFO evm_eth_compliance::statetest::runner: UC : "smodNonConst"
2023-01-27T07:49:13.643340Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618820,
    events_root: None,
}
2023-01-27T07:49:13.643345Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:13.643347Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "smodNonConst"::Merge::0
2023-01-27T07:49:13.643349Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/smodNonConst.json"
2023-01-27T07:49:13.643352Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:13.643353Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:13.643449Z  INFO evm_eth_compliance::statetest::runner: UC : "smodNonConst"
2023-01-27T07:49:13.643453Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618820,
    events_root: None,
}
2023-01-27T07:49:13.645166Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:375.453833ms
2023-01-27T07:49:13.909792Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sstoreNonConst.json", Total Files :: 1
2023-01-27T07:49:13.945009Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:49:13.945182Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:13.945188Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:49:13.945245Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:13.945347Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:13.945352Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sstoreNonConst"::Istanbul::0
2023-01-27T07:49:13.945356Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sstoreNonConst.json"
2023-01-27T07:49:13.945360Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:13.945362Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:14.371685Z  INFO evm_eth_compliance::statetest::runner: UC : "sstoreNonConst"
2023-01-27T07:49:14.371700Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1617261,
    events_root: None,
}
2023-01-27T07:49:14.371713Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:14.371718Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sstoreNonConst"::Istanbul::0
2023-01-27T07:49:14.371722Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sstoreNonConst.json"
2023-01-27T07:49:14.371726Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:14.371728Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:14.371851Z  INFO evm_eth_compliance::statetest::runner: UC : "sstoreNonConst"
2023-01-27T07:49:14.371856Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1617261,
    events_root: None,
}
2023-01-27T07:49:14.371863Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:14.371865Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sstoreNonConst"::Berlin::0
2023-01-27T07:49:14.371868Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sstoreNonConst.json"
2023-01-27T07:49:14.371871Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:14.371874Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:14.371978Z  INFO evm_eth_compliance::statetest::runner: UC : "sstoreNonConst"
2023-01-27T07:49:14.371982Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1617261,
    events_root: None,
}
2023-01-27T07:49:14.371989Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:14.371991Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sstoreNonConst"::Berlin::0
2023-01-27T07:49:14.371994Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sstoreNonConst.json"
2023-01-27T07:49:14.371998Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:14.372000Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:14.372104Z  INFO evm_eth_compliance::statetest::runner: UC : "sstoreNonConst"
2023-01-27T07:49:14.372108Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1617261,
    events_root: None,
}
2023-01-27T07:49:14.372114Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:14.372117Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sstoreNonConst"::London::0
2023-01-27T07:49:14.372120Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sstoreNonConst.json"
2023-01-27T07:49:14.372123Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:14.372125Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:14.372227Z  INFO evm_eth_compliance::statetest::runner: UC : "sstoreNonConst"
2023-01-27T07:49:14.372232Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1617261,
    events_root: None,
}
2023-01-27T07:49:14.372238Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:14.372240Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sstoreNonConst"::London::0
2023-01-27T07:49:14.372243Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sstoreNonConst.json"
2023-01-27T07:49:14.372246Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:14.372249Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:14.372350Z  INFO evm_eth_compliance::statetest::runner: UC : "sstoreNonConst"
2023-01-27T07:49:14.372355Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1617261,
    events_root: None,
}
2023-01-27T07:49:14.372361Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:14.372365Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sstoreNonConst"::Merge::0
2023-01-27T07:49:14.372369Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sstoreNonConst.json"
2023-01-27T07:49:14.372372Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:14.372374Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:14.372476Z  INFO evm_eth_compliance::statetest::runner: UC : "sstoreNonConst"
2023-01-27T07:49:14.372480Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1617261,
    events_root: None,
}
2023-01-27T07:49:14.372486Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:14.372489Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sstoreNonConst"::Merge::0
2023-01-27T07:49:14.372492Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/sstoreNonConst.json"
2023-01-27T07:49:14.372496Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:14.372498Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:14.372598Z  INFO evm_eth_compliance::statetest::runner: UC : "sstoreNonConst"
2023-01-27T07:49:14.372603Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1617261,
    events_root: None,
}
2023-01-27T07:49:14.374356Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:427.605009ms
2023-01-27T07:49:14.648832Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/subNonConst.json", Total Files :: 1
2023-01-27T07:49:14.678378Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:49:14.678517Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:14.678521Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:49:14.678575Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:14.678647Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:14.678649Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "subNonConst"::Istanbul::0
2023-01-27T07:49:14.678652Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/subNonConst.json"
2023-01-27T07:49:14.678655Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:14.678657Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:15.054426Z  INFO evm_eth_compliance::statetest::runner: UC : "subNonConst"
2023-01-27T07:49:15.054444Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618948,
    events_root: None,
}
2023-01-27T07:49:15.054457Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:15.054462Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "subNonConst"::Istanbul::0
2023-01-27T07:49:15.054465Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/subNonConst.json"
2023-01-27T07:49:15.054469Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:15.054471Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:15.054656Z  INFO evm_eth_compliance::statetest::runner: UC : "subNonConst"
2023-01-27T07:49:15.054661Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618948,
    events_root: None,
}
2023-01-27T07:49:15.054668Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:15.054671Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "subNonConst"::Berlin::0
2023-01-27T07:49:15.054673Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/subNonConst.json"
2023-01-27T07:49:15.054678Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:15.054680Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:15.054810Z  INFO evm_eth_compliance::statetest::runner: UC : "subNonConst"
2023-01-27T07:49:15.054829Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618948,
    events_root: None,
}
2023-01-27T07:49:15.054845Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:15.054853Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "subNonConst"::Berlin::0
2023-01-27T07:49:15.054862Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/subNonConst.json"
2023-01-27T07:49:15.054870Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:15.054872Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:15.055006Z  INFO evm_eth_compliance::statetest::runner: UC : "subNonConst"
2023-01-27T07:49:15.055011Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618948,
    events_root: None,
}
2023-01-27T07:49:15.055017Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:15.055021Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "subNonConst"::London::0
2023-01-27T07:49:15.055023Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/subNonConst.json"
2023-01-27T07:49:15.055027Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:15.055028Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:15.055152Z  INFO evm_eth_compliance::statetest::runner: UC : "subNonConst"
2023-01-27T07:49:15.055157Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618948,
    events_root: None,
}
2023-01-27T07:49:15.055165Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:15.055168Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "subNonConst"::London::0
2023-01-27T07:49:15.055171Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/subNonConst.json"
2023-01-27T07:49:15.055175Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:15.055176Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:15.055301Z  INFO evm_eth_compliance::statetest::runner: UC : "subNonConst"
2023-01-27T07:49:15.055306Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618948,
    events_root: None,
}
2023-01-27T07:49:15.055313Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:15.055315Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "subNonConst"::Merge::0
2023-01-27T07:49:15.055317Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/subNonConst.json"
2023-01-27T07:49:15.055319Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:15.055320Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:15.055438Z  INFO evm_eth_compliance::statetest::runner: UC : "subNonConst"
2023-01-27T07:49:15.055443Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618948,
    events_root: None,
}
2023-01-27T07:49:15.055449Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:15.055451Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "subNonConst"::Merge::0
2023-01-27T07:49:15.055453Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/subNonConst.json"
2023-01-27T07:49:15.055456Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:15.055458Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:15.055569Z  INFO evm_eth_compliance::statetest::runner: UC : "subNonConst"
2023-01-27T07:49:15.055574Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618948,
    events_root: None,
}
2023-01-27T07:49:15.057620Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:377.205623ms
2023-01-27T07:49:15.346203Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/suicideNonConst.json", Total Files :: 1
2023-01-27T07:49:15.405390Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:49:15.405576Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:15.405581Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:49:15.405655Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:15.405760Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:15.405766Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideNonConst"::Istanbul::0
2023-01-27T07:49:15.405770Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/suicideNonConst.json"
2023-01-27T07:49:15.405774Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:15.405776Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:15.772670Z  INFO evm_eth_compliance::statetest::runner: UC : "suicideNonConst"
2023-01-27T07:49:15.772687Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3404987,
    events_root: None,
}
2023-01-27T07:49:15.772697Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:15.772701Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideNonConst"::Istanbul::0
2023-01-27T07:49:15.772703Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/suicideNonConst.json"
2023-01-27T07:49:15.772706Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:15.772707Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:15.772801Z  INFO evm_eth_compliance::statetest::runner: UC : "suicideNonConst"
2023-01-27T07:49:15.772805Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-27T07:49:15.772810Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:15.772812Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideNonConst"::Berlin::0
2023-01-27T07:49:15.772814Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/suicideNonConst.json"
2023-01-27T07:49:15.772817Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:15.772818Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:15.772893Z  INFO evm_eth_compliance::statetest::runner: UC : "suicideNonConst"
2023-01-27T07:49:15.772915Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-27T07:49:15.772923Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:15.772926Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideNonConst"::Berlin::0
2023-01-27T07:49:15.772928Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/suicideNonConst.json"
2023-01-27T07:49:15.772931Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:15.772933Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:15.773013Z  INFO evm_eth_compliance::statetest::runner: UC : "suicideNonConst"
2023-01-27T07:49:15.773017Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-27T07:49:15.773022Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:15.773024Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideNonConst"::London::0
2023-01-27T07:49:15.773025Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/suicideNonConst.json"
2023-01-27T07:49:15.773028Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:15.773029Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:15.773099Z  INFO evm_eth_compliance::statetest::runner: UC : "suicideNonConst"
2023-01-27T07:49:15.773102Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-27T07:49:15.773108Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:15.773110Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideNonConst"::London::0
2023-01-27T07:49:15.773112Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/suicideNonConst.json"
2023-01-27T07:49:15.773114Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:15.773116Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:15.773184Z  INFO evm_eth_compliance::statetest::runner: UC : "suicideNonConst"
2023-01-27T07:49:15.773187Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-27T07:49:15.773192Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:15.773194Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideNonConst"::Merge::0
2023-01-27T07:49:15.773195Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/suicideNonConst.json"
2023-01-27T07:49:15.773198Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:15.773200Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:15.773268Z  INFO evm_eth_compliance::statetest::runner: UC : "suicideNonConst"
2023-01-27T07:49:15.773272Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-27T07:49:15.773276Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:15.773278Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideNonConst"::Merge::0
2023-01-27T07:49:15.773280Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/suicideNonConst.json"
2023-01-27T07:49:15.773282Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:15.773284Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:15.773364Z  INFO evm_eth_compliance::statetest::runner: UC : "suicideNonConst"
2023-01-27T07:49:15.773368Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-27T07:49:15.775406Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:367.987409ms
2023-01-27T07:49:16.062405Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/xorNonConst.json", Total Files :: 1
2023-01-27T07:49:16.096347Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-27T07:49:16.096482Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:16.096486Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-27T07:49:16.096540Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-27T07:49:16.096612Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:16.096614Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "xorNonConst"::Istanbul::0
2023-01-27T07:49:16.096617Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/xorNonConst.json"
2023-01-27T07:49:16.096620Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:16.096622Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:16.496016Z  INFO evm_eth_compliance::statetest::runner: UC : "xorNonConst"
2023-01-27T07:49:16.496031Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618736,
    events_root: None,
}
2023-01-27T07:49:16.496042Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-27T07:49:16.496046Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "xorNonConst"::Istanbul::0
2023-01-27T07:49:16.496047Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/xorNonConst.json"
2023-01-27T07:49:16.496050Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:16.496051Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:16.496172Z  INFO evm_eth_compliance::statetest::runner: UC : "xorNonConst"
2023-01-27T07:49:16.496176Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618736,
    events_root: None,
}
2023-01-27T07:49:16.496181Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:16.496183Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "xorNonConst"::Berlin::0
2023-01-27T07:49:16.496185Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/xorNonConst.json"
2023-01-27T07:49:16.496187Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:16.496188Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:16.496281Z  INFO evm_eth_compliance::statetest::runner: UC : "xorNonConst"
2023-01-27T07:49:16.496285Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618736,
    events_root: None,
}
2023-01-27T07:49:16.496289Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-27T07:49:16.496291Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "xorNonConst"::Berlin::0
2023-01-27T07:49:16.496293Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/xorNonConst.json"
2023-01-27T07:49:16.496296Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:16.496297Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:16.496387Z  INFO evm_eth_compliance::statetest::runner: UC : "xorNonConst"
2023-01-27T07:49:16.496390Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618736,
    events_root: None,
}
2023-01-27T07:49:16.496395Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:16.496397Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "xorNonConst"::London::0
2023-01-27T07:49:16.496399Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/xorNonConst.json"
2023-01-27T07:49:16.496401Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:16.496403Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:16.496491Z  INFO evm_eth_compliance::statetest::runner: UC : "xorNonConst"
2023-01-27T07:49:16.496495Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618736,
    events_root: None,
}
2023-01-27T07:49:16.496500Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-27T07:49:16.496502Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "xorNonConst"::London::0
2023-01-27T07:49:16.496504Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/xorNonConst.json"
2023-01-27T07:49:16.496506Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:16.496508Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:16.496596Z  INFO evm_eth_compliance::statetest::runner: UC : "xorNonConst"
2023-01-27T07:49:16.496600Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618736,
    events_root: None,
}
2023-01-27T07:49:16.496605Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:16.496607Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "xorNonConst"::Merge::0
2023-01-27T07:49:16.496609Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/xorNonConst.json"
2023-01-27T07:49:16.496611Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:16.496613Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:16.496703Z  INFO evm_eth_compliance::statetest::runner: UC : "xorNonConst"
2023-01-27T07:49:16.496707Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618736,
    events_root: None,
}
2023-01-27T07:49:16.496712Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-27T07:49:16.496713Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "xorNonConst"::Merge::0
2023-01-27T07:49:16.496715Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stArgsZeroOneBalance/xorNonConst.json"
2023-01-27T07:49:16.496719Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-27T07:49:16.496721Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-27T07:49:16.496834Z  INFO evm_eth_compliance::statetest::runner: UC : "xorNonConst"
2023-01-27T07:49:16.496839Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1618736,
    events_root: None,
}
2023-01-27T07:49:16.498483Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:400.502534ms
```
