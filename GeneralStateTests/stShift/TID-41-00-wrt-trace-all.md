> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stShift

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stShift \
	cargo run --release \
	-- \
	statetest
```

> For Review

* Execution Looks OK, all use-cases passed.

> Execution Trace

```
2023-01-24T15:32:23.415692Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/sar00.json", Total Files :: 1
2023-01-24T15:32:23.481799Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:23.481994Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:23.481998Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:23.482052Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:23.482122Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:23.482125Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar00"::Istanbul::0
2023-01-24T15:32:23.482128Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar00.json"
2023-01-24T15:32:23.482130Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:23.482132Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:23.850613Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1528369,
    events_root: None,
}
2023-01-24T15:32:23.850635Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:23.850644Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar00"::Berlin::0
2023-01-24T15:32:23.850646Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar00.json"
2023-01-24T15:32:23.850649Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:23.850651Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:23.850773Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1528369,
    events_root: None,
}
2023-01-24T15:32:23.850781Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:23.850783Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar00"::London::0
2023-01-24T15:32:23.850785Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar00.json"
2023-01-24T15:32:23.850787Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:23.850788Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:23.850875Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1528369,
    events_root: None,
}
2023-01-24T15:32:23.850883Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:23.850885Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar00"::Merge::0
2023-01-24T15:32:23.850887Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar00.json"
2023-01-24T15:32:23.850889Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:23.850891Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:23.850975Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1528369,
    events_root: None,
}
2023-01-24T15:32:23.852571Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:369.187489ms
2023-01-24T15:32:24.132353Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/sar01.json", Total Files :: 1
2023-01-24T15:32:24.161915Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:24.162143Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:24.162149Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:24.162216Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:24.162292Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:24.162295Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar01"::Istanbul::0
2023-01-24T15:32:24.162297Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar01.json"
2023-01-24T15:32:24.162301Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:24.162302Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:24.501132Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1528369,
    events_root: None,
}
2023-01-24T15:32:24.501155Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:24.501165Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar01"::Berlin::0
2023-01-24T15:32:24.501168Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar01.json"
2023-01-24T15:32:24.501172Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:24.501174Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:24.501297Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1528369,
    events_root: None,
}
2023-01-24T15:32:24.501305Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:24.501308Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar01"::London::0
2023-01-24T15:32:24.501311Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar01.json"
2023-01-24T15:32:24.501314Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:24.501316Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:24.501405Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1528369,
    events_root: None,
}
2023-01-24T15:32:24.501414Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:24.501417Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar01"::Merge::0
2023-01-24T15:32:24.501419Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar01.json"
2023-01-24T15:32:24.501422Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:24.501424Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:24.501520Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1528369,
    events_root: None,
}
2023-01-24T15:32:24.503222Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:339.618065ms
2023-01-24T15:32:24.777533Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/sar10.json", Total Files :: 1
2023-01-24T15:32:24.807474Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:24.807707Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:24.807712Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:24.807787Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:24.807864Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:24.807867Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar10"::Istanbul::0
2023-01-24T15:32:24.807870Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar10.json"
2023-01-24T15:32:24.807872Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:24.807874Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:25.178767Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2453643,
    events_root: None,
}
2023-01-24T15:32:25.178787Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:25.178794Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar10"::Berlin::0
2023-01-24T15:32:25.178797Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar10.json"
2023-01-24T15:32:25.178800Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:25.178801Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:25.178929Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1557945,
    events_root: None,
}
2023-01-24T15:32:25.178936Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:25.178938Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar10"::London::0
2023-01-24T15:32:25.178940Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar10.json"
2023-01-24T15:32:25.178942Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:25.178944Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:25.179031Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1557945,
    events_root: None,
}
2023-01-24T15:32:25.179038Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:25.179040Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar10"::Merge::0
2023-01-24T15:32:25.179042Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar10.json"
2023-01-24T15:32:25.179044Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:25.179047Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:25.179137Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1557945,
    events_root: None,
}
2023-01-24T15:32:25.180762Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:371.674156ms
2023-01-24T15:32:25.448621Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/sar11.json", Total Files :: 1
2023-01-24T15:32:25.477429Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:25.477637Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:25.477641Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:25.477695Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:25.477764Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:25.477768Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar11"::Istanbul::0
2023-01-24T15:32:25.477770Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar11.json"
2023-01-24T15:32:25.477773Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:25.477774Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:25.880389Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529121,
    events_root: None,
}
2023-01-24T15:32:25.880415Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:25.880421Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar11"::Berlin::0
2023-01-24T15:32:25.880424Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar11.json"
2023-01-24T15:32:25.880428Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:25.880429Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:25.880561Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529121,
    events_root: None,
}
2023-01-24T15:32:25.880572Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:25.880575Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar11"::London::0
2023-01-24T15:32:25.880577Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar11.json"
2023-01-24T15:32:25.880580Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:25.880582Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:25.880691Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529121,
    events_root: None,
}
2023-01-24T15:32:25.880699Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:25.880701Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar11"::Merge::0
2023-01-24T15:32:25.880703Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar11.json"
2023-01-24T15:32:25.880705Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:25.880707Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:25.880795Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529121,
    events_root: None,
}
2023-01-24T15:32:25.882488Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:403.378512ms
2023-01-24T15:32:26.137033Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/sar_0_256-1.json", Total Files :: 1
2023-01-24T15:32:26.169176Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:26.169384Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:26.169388Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:26.169447Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:26.169536Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:26.169540Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_0_256-1"::Istanbul::0
2023-01-24T15:32:26.169542Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_0_256-1.json"
2023-01-24T15:32:26.169545Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:26.169547Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:26.531060Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2504565,
    events_root: None,
}
2023-01-24T15:32:26.531082Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:26.531088Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_0_256-1"::Berlin::0
2023-01-24T15:32:26.531091Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_0_256-1.json"
2023-01-24T15:32:26.531094Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:26.531095Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:26.531215Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1561387,
    events_root: None,
}
2023-01-24T15:32:26.531223Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:26.531225Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_0_256-1"::London::0
2023-01-24T15:32:26.531227Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_0_256-1.json"
2023-01-24T15:32:26.531229Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:26.531231Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:26.531316Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1561387,
    events_root: None,
}
2023-01-24T15:32:26.531323Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:26.531325Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_0_256-1"::Merge::0
2023-01-24T15:32:26.531327Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_0_256-1.json"
2023-01-24T15:32:26.531329Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:26.531331Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:26.531417Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1561387,
    events_root: None,
}
2023-01-24T15:32:26.532962Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:362.252808ms
2023-01-24T15:32:26.813374Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/sar_2^254_254.json", Total Files :: 1
2023-01-24T15:32:26.876457Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:26.876659Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:26.876663Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:26.876720Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:26.876796Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:26.876800Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^254_254"::Istanbul::0
2023-01-24T15:32:26.876803Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^254_254.json"
2023-01-24T15:32:26.876806Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:26.876808Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:27.243947Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2459322,
    events_root: None,
}
2023-01-24T15:32:27.243970Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:27.243976Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^254_254"::Berlin::0
2023-01-24T15:32:27.243979Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^254_254.json"
2023-01-24T15:32:27.243982Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:27.243983Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:27.244112Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559543,
    events_root: None,
}
2023-01-24T15:32:27.244119Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:27.244121Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^254_254"::London::0
2023-01-24T15:32:27.244124Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^254_254.json"
2023-01-24T15:32:27.244126Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:27.244127Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:27.244221Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559543,
    events_root: None,
}
2023-01-24T15:32:27.244227Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:27.244230Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^254_254"::Merge::0
2023-01-24T15:32:27.244232Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^254_254.json"
2023-01-24T15:32:27.244235Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:27.244236Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:27.244328Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559543,
    events_root: None,
}
2023-01-24T15:32:27.245921Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:367.883824ms
2023-01-24T15:32:27.518448Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255-1_248.json", Total Files :: 1
2023-01-24T15:32:27.549817Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:27.550029Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:27.550033Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:27.550090Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:27.550171Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:27.550174Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^255-1_248"::Istanbul::0
2023-01-24T15:32:27.550177Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255-1_248.json"
2023-01-24T15:32:27.550180Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:27.550182Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:27.923272Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2459278,
    events_root: None,
}
2023-01-24T15:32:27.923306Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:27.923316Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^255-1_248"::Berlin::0
2023-01-24T15:32:27.923320Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255-1_248.json"
2023-01-24T15:32:27.923323Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:27.923325Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:27.923473Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559499,
    events_root: None,
}
2023-01-24T15:32:27.923482Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:27.923484Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^255-1_248"::London::0
2023-01-24T15:32:27.923486Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255-1_248.json"
2023-01-24T15:32:27.923488Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:27.923490Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:27.923583Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559499,
    events_root: None,
}
2023-01-24T15:32:27.923589Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:27.923592Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^255-1_248"::Merge::0
2023-01-24T15:32:27.923594Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255-1_248.json"
2023-01-24T15:32:27.923596Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:27.923598Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:27.923702Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559499,
    events_root: None,
}
2023-01-24T15:32:27.925543Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:373.897174ms
2023-01-24T15:32:28.197225Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255-1_254.json", Total Files :: 1
2023-01-24T15:32:28.226839Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:28.227040Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:28.227046Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:28.227104Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:28.227180Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:28.227184Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^255-1_254"::Istanbul::0
2023-01-24T15:32:28.227188Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255-1_254.json"
2023-01-24T15:32:28.227192Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:28.227194Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:28.600946Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2459278,
    events_root: None,
}
2023-01-24T15:32:28.600970Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:28.600981Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^255-1_254"::Berlin::0
2023-01-24T15:32:28.600985Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255-1_254.json"
2023-01-24T15:32:28.600988Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:28.600990Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:28.601143Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559499,
    events_root: None,
}
2023-01-24T15:32:28.601151Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:28.601154Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^255-1_254"::London::0
2023-01-24T15:32:28.601157Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255-1_254.json"
2023-01-24T15:32:28.601160Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:28.601162Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:28.601257Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559499,
    events_root: None,
}
2023-01-24T15:32:28.601264Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:28.601268Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^255-1_254"::Merge::0
2023-01-24T15:32:28.601270Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255-1_254.json"
2023-01-24T15:32:28.601274Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:28.601276Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:28.601368Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559499,
    events_root: None,
}
2023-01-24T15:32:28.602877Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:374.54139ms
2023-01-24T15:32:28.862661Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255-1_255.json", Total Files :: 1
2023-01-24T15:32:28.917640Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:28.917837Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:28.917841Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:28.917899Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:28.917974Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:28.917978Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^255-1_255"::Istanbul::0
2023-01-24T15:32:28.917982Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255-1_255.json"
2023-01-24T15:32:28.917986Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:28.917988Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:29.276243Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1530407,
    events_root: None,
}
2023-01-24T15:32:29.276264Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:29.276273Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^255-1_255"::Berlin::0
2023-01-24T15:32:29.276276Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255-1_255.json"
2023-01-24T15:32:29.276280Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:29.276282Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:29.276418Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1530407,
    events_root: None,
}
2023-01-24T15:32:29.276426Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:29.276430Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^255-1_255"::London::0
2023-01-24T15:32:29.276432Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255-1_255.json"
2023-01-24T15:32:29.276435Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:29.276436Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:29.276525Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1530407,
    events_root: None,
}
2023-01-24T15:32:29.276533Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:29.276536Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^255-1_255"::Merge::0
2023-01-24T15:32:29.276539Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255-1_255.json"
2023-01-24T15:32:29.276542Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:29.276544Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:29.276631Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1530407,
    events_root: None,
}
2023-01-24T15:32:29.278360Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:359.003666ms
2023-01-24T15:32:29.537133Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255-1_256.json", Total Files :: 1
2023-01-24T15:32:29.576021Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:29.576211Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:29.576215Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:29.576271Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:29.576340Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:29.576343Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^255-1_256"::Istanbul::0
2023-01-24T15:32:29.576346Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255-1_256.json"
2023-01-24T15:32:29.576349Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:29.576350Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:29.965100Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1530065,
    events_root: None,
}
2023-01-24T15:32:29.965124Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:29.965131Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^255-1_256"::Berlin::0
2023-01-24T15:32:29.965134Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255-1_256.json"
2023-01-24T15:32:29.965137Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:29.965138Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:29.965258Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1530065,
    events_root: None,
}
2023-01-24T15:32:29.965265Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:29.965268Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^255-1_256"::London::0
2023-01-24T15:32:29.965271Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255-1_256.json"
2023-01-24T15:32:29.965273Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:29.965275Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:29.965358Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1530065,
    events_root: None,
}
2023-01-24T15:32:29.965364Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:29.965367Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^255-1_256"::Merge::0
2023-01-24T15:32:29.965369Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255-1_256.json"
2023-01-24T15:32:29.965371Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:29.965373Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:29.965456Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1530065,
    events_root: None,
}
2023-01-24T15:32:29.967051Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:389.446637ms
2023-01-24T15:32:30.245230Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255_1.json", Total Files :: 1
2023-01-24T15:32:30.275501Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:30.275700Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:30.275704Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:30.275760Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:30.275832Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:30.275835Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^255_1"::Istanbul::0
2023-01-24T15:32:30.275838Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255_1.json"
2023-01-24T15:32:30.275841Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:30.275842Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:30.631257Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2504551,
    events_root: None,
}
2023-01-24T15:32:30.631280Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:30.631287Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^255_1"::Berlin::0
2023-01-24T15:32:30.631290Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255_1.json"
2023-01-24T15:32:30.631293Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:30.631294Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:30.631426Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1561373,
    events_root: None,
}
2023-01-24T15:32:30.631433Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:30.631436Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^255_1"::London::0
2023-01-24T15:32:30.631438Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255_1.json"
2023-01-24T15:32:30.631440Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:30.631444Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:30.631534Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1561373,
    events_root: None,
}
2023-01-24T15:32:30.631541Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:30.631544Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^255_1"::Merge::0
2023-01-24T15:32:30.631546Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255_1.json"
2023-01-24T15:32:30.631548Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:30.631549Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:30.631636Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1561373,
    events_root: None,
}
2023-01-24T15:32:30.633095Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:356.145712ms
2023-01-24T15:32:30.901844Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255_255.json", Total Files :: 1
2023-01-24T15:32:30.958131Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:30.958345Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:30.958349Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:30.958407Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:30.958484Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:30.958488Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^255_255"::Istanbul::0
2023-01-24T15:32:30.958490Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255_255.json"
2023-01-24T15:32:30.958494Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:30.958496Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:31.356020Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2504019,
    events_root: None,
}
2023-01-24T15:32:31.356046Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:31.356054Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^255_255"::Berlin::0
2023-01-24T15:32:31.356058Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255_255.json"
2023-01-24T15:32:31.356061Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:31.356063Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:31.356172Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1560841,
    events_root: None,
}
2023-01-24T15:32:31.356182Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:31.356185Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^255_255"::London::0
2023-01-24T15:32:31.356187Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255_255.json"
2023-01-24T15:32:31.356191Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:31.356193Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:31.356287Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1560841,
    events_root: None,
}
2023-01-24T15:32:31.356295Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:31.356298Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^255_255"::Merge::0
2023-01-24T15:32:31.356302Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255_255.json"
2023-01-24T15:32:31.356305Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:31.356308Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:31.356402Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1560841,
    events_root: None,
}
2023-01-24T15:32:31.358083Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:398.286039ms
2023-01-24T15:32:31.642488Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255_256.json", Total Files :: 1
2023-01-24T15:32:31.696425Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:31.696621Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:31.696626Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:31.696683Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:31.696757Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:31.696761Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^255_256"::Istanbul::0
2023-01-24T15:32:31.696765Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255_256.json"
2023-01-24T15:32:31.696769Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:31.696771Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:32.057730Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2503113,
    events_root: None,
}
2023-01-24T15:32:32.057756Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:32.057766Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^255_256"::Berlin::0
2023-01-24T15:32:32.057769Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255_256.json"
2023-01-24T15:32:32.057773Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:32.057775Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:32.057921Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559935,
    events_root: None,
}
2023-01-24T15:32:32.057946Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:32.057955Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^255_256"::London::0
2023-01-24T15:32:32.057963Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255_256.json"
2023-01-24T15:32:32.057971Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:32.057978Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:32.058109Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559935,
    events_root: None,
}
2023-01-24T15:32:32.058130Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:32.058138Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^255_256"::Merge::0
2023-01-24T15:32:32.058146Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255_256.json"
2023-01-24T15:32:32.058154Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:32.058161Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:32.058290Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559935,
    events_root: None,
}
2023-01-24T15:32:32.060367Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:361.890273ms
2023-01-24T15:32:32.346596Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255_257.json", Total Files :: 1
2023-01-24T15:32:32.382763Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:32.382983Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:32.382988Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:32.383054Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:32.383137Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:32.383141Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^255_257"::Istanbul::0
2023-01-24T15:32:32.383144Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255_257.json"
2023-01-24T15:32:32.383147Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:32.383149Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:32.728394Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2503113,
    events_root: None,
}
2023-01-24T15:32:32.728417Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:32.728424Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^255_257"::Berlin::0
2023-01-24T15:32:32.728427Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255_257.json"
2023-01-24T15:32:32.728429Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:32.728431Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:32.728539Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559935,
    events_root: None,
}
2023-01-24T15:32:32.728546Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:32.728549Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^255_257"::London::0
2023-01-24T15:32:32.728551Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255_257.json"
2023-01-24T15:32:32.728553Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:32.728554Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:32.728642Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559935,
    events_root: None,
}
2023-01-24T15:32:32.728649Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:32.728651Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^255_257"::Merge::0
2023-01-24T15:32:32.728653Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^255_257.json"
2023-01-24T15:32:32.728655Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:32.728656Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:32.728764Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559935,
    events_root: None,
}
2023-01-24T15:32:32.730446Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:346.01539ms
2023-01-24T15:32:32.992158Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/sar_2^256-1_0.json", Total Files :: 1
2023-01-24T15:32:33.023227Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:33.023421Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:33.023425Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:33.023480Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:33.023550Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:33.023554Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^256-1_0"::Istanbul::0
2023-01-24T15:32:33.023556Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^256-1_0.json"
2023-01-24T15:32:33.023561Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:33.023562Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:33.365611Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1530513,
    events_root: None,
}
2023-01-24T15:32:33.365634Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:33.365641Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^256-1_0"::Berlin::0
2023-01-24T15:32:33.365644Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^256-1_0.json"
2023-01-24T15:32:33.365647Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:33.365648Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:33.365767Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1530513,
    events_root: None,
}
2023-01-24T15:32:33.365775Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:33.365778Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^256-1_0"::London::0
2023-01-24T15:32:33.365780Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^256-1_0.json"
2023-01-24T15:32:33.365783Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:33.365784Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:33.365868Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1530513,
    events_root: None,
}
2023-01-24T15:32:33.365874Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:33.365877Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^256-1_0"::Merge::0
2023-01-24T15:32:33.365880Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^256-1_0.json"
2023-01-24T15:32:33.365883Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:33.365885Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:33.365968Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1530513,
    events_root: None,
}
2023-01-24T15:32:33.367493Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:342.752008ms
2023-01-24T15:32:33.636044Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/sar_2^256-1_1.json", Total Files :: 1
2023-01-24T15:32:33.667206Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:33.667414Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:33.667418Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:33.667479Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:33.667554Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:33.667558Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^256-1_1"::Istanbul::0
2023-01-24T15:32:33.667562Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^256-1_1.json"
2023-01-24T15:32:33.667567Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:33.667569Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:34.024599Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2504403,
    events_root: None,
}
2023-01-24T15:32:34.024622Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:34.024631Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^256-1_1"::Berlin::0
2023-01-24T15:32:34.024634Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^256-1_1.json"
2023-01-24T15:32:34.024638Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:34.024639Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:34.024774Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1561225,
    events_root: None,
}
2023-01-24T15:32:34.024782Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:34.024785Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^256-1_1"::London::0
2023-01-24T15:32:34.024788Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^256-1_1.json"
2023-01-24T15:32:34.024791Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:34.024793Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:34.024890Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1561225,
    events_root: None,
}
2023-01-24T15:32:34.024898Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:34.024901Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^256-1_1"::Merge::0
2023-01-24T15:32:34.024905Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^256-1_1.json"
2023-01-24T15:32:34.024909Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:34.024911Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:34.025004Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1561225,
    events_root: None,
}
2023-01-24T15:32:34.026631Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:357.810649ms
2023-01-24T15:32:34.322733Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/sar_2^256-1_255.json", Total Files :: 1
2023-01-24T15:32:34.396009Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:34.396199Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:34.396203Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:34.396257Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:34.396326Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:34.396329Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^256-1_255"::Istanbul::0
2023-01-24T15:32:34.396332Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^256-1_255.json"
2023-01-24T15:32:34.396335Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:34.396336Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:34.746181Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2503975,
    events_root: None,
}
2023-01-24T15:32:34.746203Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:34.746209Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^256-1_255"::Berlin::0
2023-01-24T15:32:34.746212Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^256-1_255.json"
2023-01-24T15:32:34.746214Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:34.746216Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:34.746325Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1560797,
    events_root: None,
}
2023-01-24T15:32:34.746333Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:34.746335Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^256-1_255"::London::0
2023-01-24T15:32:34.746337Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^256-1_255.json"
2023-01-24T15:32:34.746340Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:34.746341Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:34.746426Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1560797,
    events_root: None,
}
2023-01-24T15:32:34.746433Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:34.746435Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^256-1_255"::Merge::0
2023-01-24T15:32:34.746437Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^256-1_255.json"
2023-01-24T15:32:34.746439Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:34.746441Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:34.746524Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1560797,
    events_root: None,
}
2023-01-24T15:32:34.748101Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:350.526129ms
2023-01-24T15:32:35.011081Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/sar_2^256-1_256.json", Total Files :: 1
2023-01-24T15:32:35.041895Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:35.042140Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:35.042145Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:35.042213Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:35.042306Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:35.042310Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^256-1_256"::Istanbul::0
2023-01-24T15:32:35.042313Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^256-1_256.json"
2023-01-24T15:32:35.042317Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:35.042319Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:35.459974Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2503069,
    events_root: None,
}
2023-01-24T15:32:35.459997Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:35.460003Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^256-1_256"::Berlin::0
2023-01-24T15:32:35.460006Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^256-1_256.json"
2023-01-24T15:32:35.460009Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:35.460010Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:35.460127Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559891,
    events_root: None,
}
2023-01-24T15:32:35.460134Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:35.460136Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^256-1_256"::London::0
2023-01-24T15:32:35.460138Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^256-1_256.json"
2023-01-24T15:32:35.460141Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:35.460142Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:35.460227Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559891,
    events_root: None,
}
2023-01-24T15:32:35.460233Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:35.460236Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "sar_2^256-1_256"::Merge::0
2023-01-24T15:32:35.460238Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/sar_2^256-1_256.json"
2023-01-24T15:32:35.460240Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:35.460241Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:35.460327Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559891,
    events_root: None,
}
2023-01-24T15:32:35.461704Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:418.443373ms
2023-01-24T15:32:35.735399Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/shiftCombinations.json", Total Files :: 1
2023-01-24T15:32:35.801147Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:35.801346Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:35.801350Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:35.801406Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:35.801476Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:35.801480Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shiftCombinations"::Istanbul::0
2023-01-24T15:32:35.801483Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shiftCombinations.json"
2023-01-24T15:32:35.801486Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:35.801487Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:36.180996Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 698754474,
    events_root: None,
}
2023-01-24T15:32:36.181179Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:36.181188Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shiftCombinations"::Berlin::0
2023-01-24T15:32:36.181191Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shiftCombinations.json"
2023-01-24T15:32:36.181194Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:36.181195Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:36.202014Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 501295421,
    events_root: None,
}
2023-01-24T15:32:36.202245Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:36.202251Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shiftCombinations"::London::0
2023-01-24T15:32:36.202254Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shiftCombinations.json"
2023-01-24T15:32:36.202257Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:36.202259Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:36.223084Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 501295421,
    events_root: None,
}
2023-01-24T15:32:36.223313Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:36.223320Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shiftCombinations"::Merge::0
2023-01-24T15:32:36.223323Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shiftCombinations.json"
2023-01-24T15:32:36.223326Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:36.223328Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:36.243925Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 501295421,
    events_root: None,
}
2023-01-24T15:32:36.245892Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:443.007827ms
2023-01-24T15:32:36.521761Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/shiftSignedCombinations.json", Total Files :: 1
2023-01-24T15:32:36.551773Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:36.551972Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:36.551976Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:36.552032Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:36.552104Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:36.552107Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shiftSignedCombinations"::Istanbul::0
2023-01-24T15:32:36.552111Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shiftSignedCombinations.json"
2023-01-24T15:32:36.552114Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:36.552116Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:36.940096Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 290673309,
    events_root: None,
}
2023-01-24T15:32:36.940195Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:36.940203Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shiftSignedCombinations"::Berlin::0
2023-01-24T15:32:36.940206Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shiftSignedCombinations.json"
2023-01-24T15:32:36.940209Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:36.940211Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:36.949355Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 208904396,
    events_root: None,
}
2023-01-24T15:32:36.949446Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:36.949451Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shiftSignedCombinations"::London::0
2023-01-24T15:32:36.949453Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shiftSignedCombinations.json"
2023-01-24T15:32:36.949456Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:36.949457Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:36.958780Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 208904396,
    events_root: None,
}
2023-01-24T15:32:36.958887Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:36.958893Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shiftSignedCombinations"::Merge::0
2023-01-24T15:32:36.958896Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shiftSignedCombinations.json"
2023-01-24T15:32:36.958899Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:36.958900Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:36.967845Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 208904396,
    events_root: None,
}
2023-01-24T15:32:36.969832Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:416.16422ms
2023-01-24T15:32:37.240099Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/shl01-0100.json", Total Files :: 1
2023-01-24T15:32:37.274750Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:37.274955Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:37.274959Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:37.275017Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:37.275092Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:37.275096Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl01-0100"::Istanbul::0
2023-01-24T15:32:37.275098Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl01-0100.json"
2023-01-24T15:32:37.275101Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:37.275103Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:37.646912Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1528419,
    events_root: None,
}
2023-01-24T15:32:37.646935Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:37.646942Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl01-0100"::Berlin::0
2023-01-24T15:32:37.646945Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl01-0100.json"
2023-01-24T15:32:37.646947Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:37.646948Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:37.647069Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1528419,
    events_root: None,
}
2023-01-24T15:32:37.647076Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:37.647079Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl01-0100"::London::0
2023-01-24T15:32:37.647080Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl01-0100.json"
2023-01-24T15:32:37.647084Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:37.647086Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:37.647188Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1528419,
    events_root: None,
}
2023-01-24T15:32:37.647196Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:37.647198Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl01-0100"::Merge::0
2023-01-24T15:32:37.647200Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl01-0100.json"
2023-01-24T15:32:37.647202Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:37.647204Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:37.647296Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1528419,
    events_root: None,
}
2023-01-24T15:32:37.648853Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:372.556976ms
2023-01-24T15:32:37.909825Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/shl01-0101.json", Total Files :: 1
2023-01-24T15:32:37.941610Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:37.941814Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:37.941818Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:37.941876Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:37.941952Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:37.941955Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl01-0101"::Istanbul::0
2023-01-24T15:32:37.941958Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl01-0101.json"
2023-01-24T15:32:37.941961Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:37.941963Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:38.329462Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1528419,
    events_root: None,
}
2023-01-24T15:32:38.329483Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:38.329490Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl01-0101"::Berlin::0
2023-01-24T15:32:38.329492Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl01-0101.json"
2023-01-24T15:32:38.329495Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:38.329497Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:38.329632Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1528419,
    events_root: None,
}
2023-01-24T15:32:38.329639Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:38.329642Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl01-0101"::London::0
2023-01-24T15:32:38.329644Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl01-0101.json"
2023-01-24T15:32:38.329646Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:38.329648Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:38.329734Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1528419,
    events_root: None,
}
2023-01-24T15:32:38.329741Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:38.329743Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl01-0101"::Merge::0
2023-01-24T15:32:38.329745Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl01-0101.json"
2023-01-24T15:32:38.329747Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:38.329749Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:38.329831Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1528419,
    events_root: None,
}
2023-01-24T15:32:38.331307Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:388.23162ms
2023-01-24T15:32:38.621393Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/shl01-ff.json", Total Files :: 1
2023-01-24T15:32:38.651436Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:38.651636Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:38.651640Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:38.651701Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:38.651774Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:38.651777Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl01-ff"::Istanbul::0
2023-01-24T15:32:38.651780Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl01-ff.json"
2023-01-24T15:32:38.651783Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:38.651784Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:39.023796Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2497333,
    events_root: None,
}
2023-01-24T15:32:39.023823Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:39.023831Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl01-ff"::Berlin::0
2023-01-24T15:32:39.023833Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl01-ff.json"
2023-01-24T15:32:39.023836Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:39.023837Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:39.023949Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1558934,
    events_root: None,
}
2023-01-24T15:32:39.023956Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:39.023960Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl01-ff"::London::0
2023-01-24T15:32:39.023962Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl01-ff.json"
2023-01-24T15:32:39.023964Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:39.023966Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:39.024054Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1558934,
    events_root: None,
}
2023-01-24T15:32:39.024062Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:39.024068Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl01-ff"::Merge::0
2023-01-24T15:32:39.024070Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl01-ff.json"
2023-01-24T15:32:39.024072Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:39.024073Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:39.024174Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1558934,
    events_root: None,
}
2023-01-24T15:32:39.025783Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:372.749679ms
2023-01-24T15:32:39.294221Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/shl01.json", Total Files :: 1
2023-01-24T15:32:39.328689Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:39.328894Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:39.328898Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:39.328956Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:39.329032Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:39.329035Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl01"::Istanbul::0
2023-01-24T15:32:39.329038Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl01.json"
2023-01-24T15:32:39.329041Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:39.329042Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:39.714950Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1528301,
    events_root: None,
}
2023-01-24T15:32:39.714972Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:39.714979Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl01"::Berlin::0
2023-01-24T15:32:39.714982Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl01.json"
2023-01-24T15:32:39.714984Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:39.714986Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:39.715089Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1528301,
    events_root: None,
}
2023-01-24T15:32:39.715095Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:39.715098Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl01"::London::0
2023-01-24T15:32:39.715099Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl01.json"
2023-01-24T15:32:39.715102Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:39.715103Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:39.715187Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1528301,
    events_root: None,
}
2023-01-24T15:32:39.715195Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:39.715197Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl01"::Merge::0
2023-01-24T15:32:39.715199Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl01.json"
2023-01-24T15:32:39.715201Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:39.715202Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:39.715291Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1528301,
    events_root: None,
}
2023-01-24T15:32:39.716834Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:386.615477ms
2023-01-24T15:32:39.987082Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/shl10.json", Total Files :: 1
2023-01-24T15:32:40.016457Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:40.016653Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:40.016657Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:40.016712Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:40.016785Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:40.016788Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl10"::Istanbul::0
2023-01-24T15:32:40.016791Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl10.json"
2023-01-24T15:32:40.016794Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:40.016795Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:40.405463Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2453623,
    events_root: None,
}
2023-01-24T15:32:40.405487Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:40.405495Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl10"::Berlin::0
2023-01-24T15:32:40.405498Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl10.json"
2023-01-24T15:32:40.405510Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:40.405511Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:40.405652Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1557925,
    events_root: None,
}
2023-01-24T15:32:40.405660Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:40.405663Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl10"::London::0
2023-01-24T15:32:40.405665Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl10.json"
2023-01-24T15:32:40.405669Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:40.405670Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:40.405760Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1557925,
    events_root: None,
}
2023-01-24T15:32:40.405766Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:40.405769Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl10"::Merge::0
2023-01-24T15:32:40.405771Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl10.json"
2023-01-24T15:32:40.405773Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:40.405774Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:40.405862Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1557925,
    events_root: None,
}
2023-01-24T15:32:40.407579Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:389.416649ms
2023-01-24T15:32:40.689642Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/shl11.json", Total Files :: 1
2023-01-24T15:32:40.719637Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:40.719838Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:40.719841Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:40.719898Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:40.719972Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:40.719975Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl11"::Istanbul::0
2023-01-24T15:32:40.719978Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl11.json"
2023-01-24T15:32:40.719981Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:40.719983Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:41.094448Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2453923,
    events_root: None,
}
2023-01-24T15:32:41.094479Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:41.094490Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl11"::Berlin::0
2023-01-24T15:32:41.094494Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl11.json"
2023-01-24T15:32:41.094497Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:41.094499Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:41.094636Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1558225,
    events_root: None,
}
2023-01-24T15:32:41.094645Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:41.094648Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl11"::London::0
2023-01-24T15:32:41.094651Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl11.json"
2023-01-24T15:32:41.094653Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:41.094655Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:41.094766Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1558225,
    events_root: None,
}
2023-01-24T15:32:41.094773Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:41.094775Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl11"::Merge::0
2023-01-24T15:32:41.094777Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl11.json"
2023-01-24T15:32:41.094780Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:41.094781Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:41.094872Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1558225,
    events_root: None,
}
2023-01-24T15:32:41.096759Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:375.24792ms
2023-01-24T15:32:41.381858Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/shl_-1_0.json", Total Files :: 1
2023-01-24T15:32:41.434699Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:41.434893Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:41.434897Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:41.434956Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:41.435028Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:41.435032Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl_-1_0"::Istanbul::0
2023-01-24T15:32:41.435034Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl_-1_0.json"
2023-01-24T15:32:41.435037Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:41.435039Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:41.783811Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2503363,
    events_root: None,
}
2023-01-24T15:32:41.783831Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:41.783838Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl_-1_0"::Berlin::0
2023-01-24T15:32:41.783841Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl_-1_0.json"
2023-01-24T15:32:41.783844Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:41.783845Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:41.783973Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1560185,
    events_root: None,
}
2023-01-24T15:32:41.783981Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:41.783983Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl_-1_0"::London::0
2023-01-24T15:32:41.783985Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl_-1_0.json"
2023-01-24T15:32:41.783987Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:41.783989Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:41.784079Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1560185,
    events_root: None,
}
2023-01-24T15:32:41.784086Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:41.784089Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl_-1_0"::Merge::0
2023-01-24T15:32:41.784090Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl_-1_0.json"
2023-01-24T15:32:41.784093Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:41.784094Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:41.784182Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1560185,
    events_root: None,
}
2023-01-24T15:32:41.785775Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:349.493526ms
2023-01-24T15:32:42.069020Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/shl_-1_1.json", Total Files :: 1
2023-01-24T15:32:42.099371Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:42.099567Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:42.099572Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:42.099628Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:42.099701Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:42.099705Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl_-1_1"::Istanbul::0
2023-01-24T15:32:42.099708Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl_-1_1.json"
2023-01-24T15:32:42.099711Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:42.099712Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:42.467356Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2503663,
    events_root: None,
}
2023-01-24T15:32:42.467379Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:42.467387Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl_-1_1"::Berlin::0
2023-01-24T15:32:42.467390Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl_-1_1.json"
2023-01-24T15:32:42.467393Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:42.467394Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:42.467529Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1560485,
    events_root: None,
}
2023-01-24T15:32:42.467536Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:42.467538Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl_-1_1"::London::0
2023-01-24T15:32:42.467540Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl_-1_1.json"
2023-01-24T15:32:42.467542Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:42.467544Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:42.467632Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1560485,
    events_root: None,
}
2023-01-24T15:32:42.467639Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:42.467641Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl_-1_1"::Merge::0
2023-01-24T15:32:42.467644Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl_-1_1.json"
2023-01-24T15:32:42.467646Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:42.467648Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:42.467734Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1560485,
    events_root: None,
}
2023-01-24T15:32:42.469537Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:368.373566ms
2023-01-24T15:32:42.761663Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/shl_-1_255.json", Total Files :: 1
2023-01-24T15:32:42.807732Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:42.807933Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:42.807937Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:42.807994Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:42.808067Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:42.808070Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl_-1_255"::Istanbul::0
2023-01-24T15:32:42.808073Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl_-1_255.json"
2023-01-24T15:32:42.808076Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:42.808078Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:43.162800Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2503127,
    events_root: None,
}
2023-01-24T15:32:43.162822Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:43.162829Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl_-1_255"::Berlin::0
2023-01-24T15:32:43.162831Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl_-1_255.json"
2023-01-24T15:32:43.162834Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:43.162836Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:43.162970Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559949,
    events_root: None,
}
2023-01-24T15:32:43.162977Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:43.162980Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl_-1_255"::London::0
2023-01-24T15:32:43.162982Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl_-1_255.json"
2023-01-24T15:32:43.162985Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:43.162986Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:43.163077Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559949,
    events_root: None,
}
2023-01-24T15:32:43.163084Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:43.163086Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl_-1_255"::Merge::0
2023-01-24T15:32:43.163088Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl_-1_255.json"
2023-01-24T15:32:43.163090Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:43.163092Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:43.163197Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559949,
    events_root: None,
}
2023-01-24T15:32:43.164931Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:355.477334ms
2023-01-24T15:32:43.447863Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/shl_-1_256.json", Total Files :: 1
2023-01-24T15:32:43.477977Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:43.478191Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:43.478196Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:43.478254Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:43.478340Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:43.478344Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl_-1_256"::Istanbul::0
2023-01-24T15:32:43.478347Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl_-1_256.json"
2023-01-24T15:32:43.478350Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:43.478351Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:43.893351Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529997,
    events_root: None,
}
2023-01-24T15:32:43.893373Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:43.893380Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl_-1_256"::Berlin::0
2023-01-24T15:32:43.893382Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl_-1_256.json"
2023-01-24T15:32:43.893385Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:43.893386Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:43.893516Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529997,
    events_root: None,
}
2023-01-24T15:32:43.893524Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:43.893527Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl_-1_256"::London::0
2023-01-24T15:32:43.893529Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl_-1_256.json"
2023-01-24T15:32:43.893532Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:43.893535Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:43.893630Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529997,
    events_root: None,
}
2023-01-24T15:32:43.893637Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:43.893640Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl_-1_256"::Merge::0
2023-01-24T15:32:43.893643Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl_-1_256.json"
2023-01-24T15:32:43.893645Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:43.893647Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:43.893739Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529997,
    events_root: None,
}
2023-01-24T15:32:43.895334Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:415.774371ms
2023-01-24T15:32:44.162479Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/shl_2^255-1_1.json", Total Files :: 1
2023-01-24T15:32:44.193903Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:44.194103Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:44.194107Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:44.194163Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:44.194237Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:44.194240Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl_2^255-1_1"::Istanbul::0
2023-01-24T15:32:44.194243Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl_2^255-1_1.json"
2023-01-24T15:32:44.194246Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:44.194248Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:44.546818Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2503663,
    events_root: None,
}
2023-01-24T15:32:44.546838Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:44.546846Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl_2^255-1_1"::Berlin::0
2023-01-24T15:32:44.546850Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl_2^255-1_1.json"
2023-01-24T15:32:44.546853Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:44.546855Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:44.546987Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1560485,
    events_root: None,
}
2023-01-24T15:32:44.546996Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:44.546999Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl_2^255-1_1"::London::0
2023-01-24T15:32:44.547001Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl_2^255-1_1.json"
2023-01-24T15:32:44.547004Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:44.547006Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:44.547105Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1560485,
    events_root: None,
}
2023-01-24T15:32:44.547113Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:44.547116Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shl_2^255-1_1"::Merge::0
2023-01-24T15:32:44.547118Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shl_2^255-1_1.json"
2023-01-24T15:32:44.547122Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:44.547124Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:44.547218Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1560485,
    events_root: None,
}
2023-01-24T15:32:44.548865Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:353.328255ms
2023-01-24T15:32:44.819679Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/shr01.json", Total Files :: 1
2023-01-24T15:32:44.849365Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:44.849576Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:44.849580Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:44.849636Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:44.849710Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:44.849713Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr01"::Istanbul::0
2023-01-24T15:32:44.849716Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr01.json"
2023-01-24T15:32:44.849719Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:44.849721Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:45.223765Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1528169,
    events_root: None,
}
2023-01-24T15:32:45.223787Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:45.223793Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr01"::Berlin::0
2023-01-24T15:32:45.223796Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr01.json"
2023-01-24T15:32:45.223798Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:45.223800Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:45.223902Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1528169,
    events_root: None,
}
2023-01-24T15:32:45.223909Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:45.223911Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr01"::London::0
2023-01-24T15:32:45.223913Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr01.json"
2023-01-24T15:32:45.223915Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:45.223917Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:45.224003Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1528169,
    events_root: None,
}
2023-01-24T15:32:45.224009Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:45.224011Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr01"::Merge::0
2023-01-24T15:32:45.224013Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr01.json"
2023-01-24T15:32:45.224015Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:45.224017Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:45.224101Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1528169,
    events_root: None,
}
2023-01-24T15:32:45.225518Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:374.747145ms
2023-01-24T15:32:45.494611Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/shr10.json", Total Files :: 1
2023-01-24T15:32:45.524871Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:45.525067Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:45.525071Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:45.525126Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:45.525199Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:45.525203Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr10"::Istanbul::0
2023-01-24T15:32:45.525205Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr10.json"
2023-01-24T15:32:45.525209Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:45.525210Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:45.884603Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2453447,
    events_root: None,
}
2023-01-24T15:32:45.884632Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:45.884643Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr10"::Berlin::0
2023-01-24T15:32:45.884646Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr10.json"
2023-01-24T15:32:45.884649Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:45.884651Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:45.884786Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1557749,
    events_root: None,
}
2023-01-24T15:32:45.884794Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:45.884798Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr10"::London::0
2023-01-24T15:32:45.884800Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr10.json"
2023-01-24T15:32:45.884802Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:45.884803Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:45.884897Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1557749,
    events_root: None,
}
2023-01-24T15:32:45.884904Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:45.884907Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr10"::Merge::0
2023-01-24T15:32:45.884909Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr10.json"
2023-01-24T15:32:45.884912Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:45.884913Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:45.885006Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1557749,
    events_root: None,
}
2023-01-24T15:32:45.886794Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:360.1464ms
2023-01-24T15:32:46.164080Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/shr11.json", Total Files :: 1
2023-01-24T15:32:46.200805Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:46.201029Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:46.201032Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:46.201093Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:46.201165Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:46.201169Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr11"::Istanbul::0
2023-01-24T15:32:46.201171Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr11.json"
2023-01-24T15:32:46.201174Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:46.201176Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:46.549715Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1528873,
    events_root: None,
}
2023-01-24T15:32:46.549738Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:46.549745Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr11"::Berlin::0
2023-01-24T15:32:46.549748Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr11.json"
2023-01-24T15:32:46.549752Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:46.549753Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:46.549873Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1528873,
    events_root: None,
}
2023-01-24T15:32:46.549880Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:46.549883Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr11"::London::0
2023-01-24T15:32:46.549884Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr11.json"
2023-01-24T15:32:46.549887Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:46.549888Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:46.549974Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1528873,
    events_root: None,
}
2023-01-24T15:32:46.549980Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:46.549983Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr11"::Merge::0
2023-01-24T15:32:46.549985Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr11.json"
2023-01-24T15:32:46.549987Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:46.549988Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:46.550074Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1528873,
    events_root: None,
}
2023-01-24T15:32:46.551659Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:349.28082ms
2023-01-24T15:32:46.842451Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/shr_-1_0.json", Total Files :: 1
2023-01-24T15:32:46.873539Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:46.873739Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:46.873744Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:46.873806Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:46.873878Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:46.873881Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr_-1_0"::Istanbul::0
2023-01-24T15:32:46.873884Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr_-1_0.json"
2023-01-24T15:32:46.873887Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:46.873888Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:47.235307Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2503187,
    events_root: None,
}
2023-01-24T15:32:47.235331Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:47.235339Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr_-1_0"::Berlin::0
2023-01-24T15:32:47.235341Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr_-1_0.json"
2023-01-24T15:32:47.235344Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:47.235345Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:47.235481Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1560009,
    events_root: None,
}
2023-01-24T15:32:47.235488Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:47.235490Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr_-1_0"::London::0
2023-01-24T15:32:47.235492Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr_-1_0.json"
2023-01-24T15:32:47.235494Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:47.235496Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:47.235585Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1560009,
    events_root: None,
}
2023-01-24T15:32:47.235592Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:47.235596Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr_-1_0"::Merge::0
2023-01-24T15:32:47.235598Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr_-1_0.json"
2023-01-24T15:32:47.235601Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:47.235602Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:47.235691Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1560009,
    events_root: None,
}
2023-01-24T15:32:47.237367Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:362.16322ms
2023-01-24T15:32:47.503462Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/shr_-1_1.json", Total Files :: 1
2023-01-24T15:32:47.533825Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:47.534029Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:47.534033Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:47.534089Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:47.534164Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:47.534167Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr_-1_1"::Istanbul::0
2023-01-24T15:32:47.534170Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr_-1_1.json"
2023-01-24T15:32:47.534173Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:47.534174Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:47.965738Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2503403,
    events_root: None,
}
2023-01-24T15:32:47.965766Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:47.965777Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr_-1_1"::Berlin::0
2023-01-24T15:32:47.965781Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr_-1_1.json"
2023-01-24T15:32:47.965785Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:47.965787Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:47.965937Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1560225,
    events_root: None,
}
2023-01-24T15:32:47.965962Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:47.965971Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr_-1_1"::London::0
2023-01-24T15:32:47.965979Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr_-1_1.json"
2023-01-24T15:32:47.965987Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:47.965994Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:47.966129Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1560225,
    events_root: None,
}
2023-01-24T15:32:47.966139Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:47.966142Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr_-1_1"::Merge::0
2023-01-24T15:32:47.966145Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr_-1_1.json"
2023-01-24T15:32:47.966148Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:47.966149Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:47.966275Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1560225,
    events_root: None,
}
2023-01-24T15:32:47.968709Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:432.465201ms
2023-01-24T15:32:48.297031Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/shr_-1_255.json", Total Files :: 1
2023-01-24T15:32:48.328363Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:48.328570Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:48.328574Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:48.328632Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:48.328707Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:48.328711Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr_-1_255"::Istanbul::0
2023-01-24T15:32:48.328714Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr_-1_255.json"
2023-01-24T15:32:48.328717Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:48.328719Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:48.705147Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2458946,
    events_root: None,
}
2023-01-24T15:32:48.705174Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:48.705181Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr_-1_255"::Berlin::0
2023-01-24T15:32:48.705184Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr_-1_255.json"
2023-01-24T15:32:48.705188Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:48.705189Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:48.705334Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559167,
    events_root: None,
}
2023-01-24T15:32:48.705342Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:48.705344Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr_-1_255"::London::0
2023-01-24T15:32:48.705346Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr_-1_255.json"
2023-01-24T15:32:48.705348Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:48.705350Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:48.705444Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559167,
    events_root: None,
}
2023-01-24T15:32:48.705450Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:48.705452Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr_-1_255"::Merge::0
2023-01-24T15:32:48.705454Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr_-1_255.json"
2023-01-24T15:32:48.705456Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:48.705457Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:48.705557Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559167,
    events_root: None,
}
2023-01-24T15:32:48.707423Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:377.206939ms
2023-01-24T15:32:48.973864Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/shr_-1_256.json", Total Files :: 1
2023-01-24T15:32:49.039647Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:49.039850Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:49.039856Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:49.039913Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:49.039987Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:49.039990Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr_-1_256"::Istanbul::0
2023-01-24T15:32:49.039993Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr_-1_256.json"
2023-01-24T15:32:49.039996Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:49.039997Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:49.426523Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529873,
    events_root: None,
}
2023-01-24T15:32:49.426547Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:49.426556Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr_-1_256"::Berlin::0
2023-01-24T15:32:49.426560Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr_-1_256.json"
2023-01-24T15:32:49.426564Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:49.426566Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:49.426698Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529873,
    events_root: None,
}
2023-01-24T15:32:49.426707Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:49.426710Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr_-1_256"::London::0
2023-01-24T15:32:49.426712Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr_-1_256.json"
2023-01-24T15:32:49.426716Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:49.426718Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:49.426807Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529873,
    events_root: None,
}
2023-01-24T15:32:49.426816Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:49.426819Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr_-1_256"::Merge::0
2023-01-24T15:32:49.426822Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr_-1_256.json"
2023-01-24T15:32:49.426825Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:49.426827Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:49.426916Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529873,
    events_root: None,
}
2023-01-24T15:32:49.428423Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:387.281706ms
2023-01-24T15:32:49.708570Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/shr_2^255_1.json", Total Files :: 1
2023-01-24T15:32:49.756611Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:49.756805Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:49.756808Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:49.756864Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:49.756934Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:49.756938Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr_2^255_1"::Istanbul::0
2023-01-24T15:32:49.756940Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr_2^255_1.json"
2023-01-24T15:32:49.756943Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:49.756945Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:50.099410Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2503515,
    events_root: None,
}
2023-01-24T15:32:50.099430Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:50.099437Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr_2^255_1"::Berlin::0
2023-01-24T15:32:50.099439Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr_2^255_1.json"
2023-01-24T15:32:50.099442Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:50.099443Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:50.099550Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1560337,
    events_root: None,
}
2023-01-24T15:32:50.099557Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:50.099559Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr_2^255_1"::London::0
2023-01-24T15:32:50.099561Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr_2^255_1.json"
2023-01-24T15:32:50.099563Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:50.099565Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:50.099650Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1560337,
    events_root: None,
}
2023-01-24T15:32:50.099657Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:50.099659Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr_2^255_1"::Merge::0
2023-01-24T15:32:50.099661Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr_2^255_1.json"
2023-01-24T15:32:50.099663Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:50.099665Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:50.099749Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1560337,
    events_root: None,
}
2023-01-24T15:32:50.101186Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:343.150429ms
2023-01-24T15:32:50.363920Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/shr_2^255_255.json", Total Files :: 1
2023-01-24T15:32:50.396469Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:50.396665Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:50.396669Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:50.396730Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:50.396826Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:50.396830Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr_2^255_255"::Istanbul::0
2023-01-24T15:32:50.396833Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr_2^255_255.json"
2023-01-24T15:32:50.396837Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:50.396839Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:50.766906Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2459014,
    events_root: None,
}
2023-01-24T15:32:50.766928Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:50.766936Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr_2^255_255"::Berlin::0
2023-01-24T15:32:50.766939Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr_2^255_255.json"
2023-01-24T15:32:50.766942Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:50.766944Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:50.767058Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559235,
    events_root: None,
}
2023-01-24T15:32:50.767066Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:50.767069Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr_2^255_255"::London::0
2023-01-24T15:32:50.767072Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr_2^255_255.json"
2023-01-24T15:32:50.767075Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:50.767077Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:50.767168Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559235,
    events_root: None,
}
2023-01-24T15:32:50.767175Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:50.767178Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr_2^255_255"::Merge::0
2023-01-24T15:32:50.767181Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr_2^255_255.json"
2023-01-24T15:32:50.767184Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:50.767186Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:50.767277Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559235,
    events_root: None,
}
2023-01-24T15:32:50.768574Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:370.820976ms
2023-01-24T15:32:51.050241Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/shr_2^255_256.json", Total Files :: 1
2023-01-24T15:32:51.080189Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:51.080384Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:51.080388Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:51.080446Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:51.080519Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:51.080523Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr_2^255_256"::Istanbul::0
2023-01-24T15:32:51.080527Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr_2^255_256.json"
2023-01-24T15:32:51.080531Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:51.080533Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:51.448419Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529941,
    events_root: None,
}
2023-01-24T15:32:51.448446Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:51.448456Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr_2^255_256"::Berlin::0
2023-01-24T15:32:51.448460Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr_2^255_256.json"
2023-01-24T15:32:51.448464Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:51.448465Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:51.448606Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529941,
    events_root: None,
}
2023-01-24T15:32:51.448616Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:51.448619Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr_2^255_256"::London::0
2023-01-24T15:32:51.448622Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr_2^255_256.json"
2023-01-24T15:32:51.448625Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:51.448628Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:51.448746Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529941,
    events_root: None,
}
2023-01-24T15:32:51.448755Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:51.448758Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr_2^255_256"::Merge::0
2023-01-24T15:32:51.448761Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr_2^255_256.json"
2023-01-24T15:32:51.448764Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:51.448766Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:51.448883Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529941,
    events_root: None,
}
2023-01-24T15:32:51.450907Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:368.723632ms
2023-01-24T15:32:51.736528Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "./test-vectors/tests/GeneralStateTests/stShift/shr_2^255_257.json", Total Files :: 1
2023-01-24T15:32:51.767295Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T15:32:51.767489Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:51.767493Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T15:32:51.767549Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T15:32:51.767623Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T15:32:51.767626Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr_2^255_257"::Istanbul::0
2023-01-24T15:32:51.767629Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr_2^255_257.json"
2023-01-24T15:32:51.767632Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:51.767633Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:52.105936Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529941,
    events_root: None,
}
2023-01-24T15:32:52.105957Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T15:32:52.105964Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr_2^255_257"::Berlin::0
2023-01-24T15:32:52.105966Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr_2^255_257.json"
2023-01-24T15:32:52.105969Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:52.105971Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:52.106092Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529941,
    events_root: None,
}
2023-01-24T15:32:52.106099Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T15:32:52.106102Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr_2^255_257"::London::0
2023-01-24T15:32:52.106104Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr_2^255_257.json"
2023-01-24T15:32:52.106107Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:52.106108Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:52.106193Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529941,
    events_root: None,
}
2023-01-24T15:32:52.106200Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T15:32:52.106202Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "shr_2^255_257"::Merge::0
2023-01-24T15:32:52.106204Z  INFO evm_eth_compliance::statetest::runner: Path : "./test-vectors/tests/GeneralStateTests/stShift/shr_2^255_257.json"
2023-01-24T15:32:52.106206Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T15:32:52.106208Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T15:32:52.106290Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529941,
    events_root: None,
}
2023-01-24T15:32:52.107820Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 1 Files in Time:339.006034ms
```