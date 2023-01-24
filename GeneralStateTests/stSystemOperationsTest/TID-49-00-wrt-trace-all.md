> Status

| Status | Context |
| --- | --- |
| OK | under WASM RT context |
| TODO | under native RT context |

> Test Suite

https://github.com/ethereum/tests/blob/develop/GeneralStateTests/stSystemOperationsTest

> Command to execute

```
clear && \
	RUST_LOG=evm_eth_compliance=trace \
	VECTOR=test-vectors/tests/GeneralStateTests/stSystemOperationsTest \
	cargo run --release \
	-- \
	statetest
```

> For Review

Hit with `EVM_CONTRACT_ILLEGAL_MEMORY_ACCESS`, ExitCode::38

| Test ID | Use-Case |
| --- | --- |
| TID-49-17 | stSystemOperationsTest/CallRecursiveBomb0_OOG_atMaxCallDepth ( London::0, Merge::0 ) |
| TID-49-26 | stSystemOperationsTest/CallToNameRegistratorMemOOGAndInsufficientBalance |

Hit with `SYS_ILLEGAL_INSTRUCTION`, ExitCode::4

| Test ID | Use-Case |
| --- | --- |
| TID-49-30 | stSystemOperationsTest/CallToNameRegistratorTooMuchMemory0 |

Hit with `EVM_CONTRACT_BAD_JUMPDEST`, ExitCode::39

| Test ID | Use-Case |
| --- | --- |
| TID-49-35 | stSystemOperationsTest/CallToReturn1ForDynamicJump0 |
| TID-49-36 | stSystemOperationsTest/CallToReturn1ForDynamicJump1 |

Hit with `EVM_CONTRACT_UNDEFINED_INSTRUCTION`, ExitCode::35

| Test ID | Use-Case |
| --- | --- |
| TID-49-09 | stSystemOperationsTest/callcodeTo0 |
| TID-49-10 | stSystemOperationsTest/callcodeToNameRegistrator0 |
| TID-49-11 | stSystemOperationsTest/callcodeToNameRegistratorAddresTooBigLeft |
| TID-49-12 | stSystemOperationsTest/callcodeToNameRegistratorAddresTooBigRight |
| TID-49-13 | stSystemOperationsTest/callcodeToNameRegistratorZeroMemExpanion |
| TID-49-14 | stSystemOperationsTest/callcodeToReturn1 |

Hit with `EVM_CONTRACT_ILLEGAL_MEMORY_ACCESS`, ExitCode::38

| Test ID | Use-Case |
| --- | --- |
| TID-49-42 | stSystemOperationsTest/createNameRegistratorOutOfMemoryBonds0 |
| TID-49-43 | stSystemOperationsTest/createNameRegistratorOutOfMemoryBonds1 |

> Execution Trace

```
2023-01-24T10:15:32.057624Z  INFO evm_eth_compliance::statetest::cmd: Start running tests on: Path :: "test-vectors/tests/GeneralStateTests/stSystemOperationsTest", Total Files :: 67
2023-01-24T10:15:32.057877Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls0.json"
2023-01-24T10:15:32.087759Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:32.087956Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:32.087960Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:32.088015Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:32.088018Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:15:32.088081Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:32.088152Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:32.088155Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ABAcalls0"::Istanbul::0
2023-01-24T10:15:32.088158Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls0.json"
2023-01-24T10:15:32.088161Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:32.088163Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:32.443519Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1810085,
    events_root: None,
}
2023-01-24T10:15:32.443538Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:32.443545Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ABAcalls0"::Berlin::0
2023-01-24T10:15:32.443548Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls0.json"
2023-01-24T10:15:32.443551Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:32.443552Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:32.443677Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1810085,
    events_root: None,
}
2023-01-24T10:15:32.443693Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:32.443696Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ABAcalls0"::London::0
2023-01-24T10:15:32.443698Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls0.json"
2023-01-24T10:15:32.443700Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:32.443702Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:32.443815Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1810085,
    events_root: None,
}
2023-01-24T10:15:32.443822Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:32.443825Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ABAcalls0"::Merge::0
2023-01-24T10:15:32.443827Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls0.json"
2023-01-24T10:15:32.443829Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:32.443831Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:32.443942Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1810085,
    events_root: None,
}
2023-01-24T10:15:32.445523Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls0.json"
2023-01-24T10:15:32.445557Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls1.json"
2023-01-24T10:15:32.472391Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:32.472493Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:32.472496Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:32.472551Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:32.472553Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:15:32.472621Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:32.472700Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:32.472706Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ABAcalls1"::Istanbul::0
2023-01-24T10:15:32.472709Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls1.json"
2023-01-24T10:15:32.472713Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:32.472716Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:33.004276Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2088517500,
    events_root: None,
}
2023-01-24T10:15:33.008815Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:33.008829Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ABAcalls1"::Berlin::0
2023-01-24T10:15:33.008831Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls1.json"
2023-01-24T10:15:33.008835Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:33.008836Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:33.117782Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1611885767,
    events_root: None,
}
2023-01-24T10:15:33.122222Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:33.122237Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ABAcalls1"::London::0
2023-01-24T10:15:33.122240Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls1.json"
2023-01-24T10:15:33.122244Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:33.122246Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:33.231460Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1611885767,
    events_root: None,
}
2023-01-24T10:15:33.236414Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:33.236431Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ABAcalls1"::Merge::0
2023-01-24T10:15:33.236434Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls1.json"
2023-01-24T10:15:33.236437Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:33.236438Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:33.348090Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1611885767,
    events_root: None,
}
2023-01-24T10:15:33.364218Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls1.json"
2023-01-24T10:15:33.364262Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls2.json"
2023-01-24T10:15:33.388195Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:33.388307Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:33.388312Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:33.388369Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:33.388372Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:15:33.388435Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:33.388509Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:33.388515Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ABAcalls2"::Istanbul::0
2023-01-24T10:15:33.388518Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls2.json"
2023-01-24T10:15:33.388522Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:33.388524Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:33.887383Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3034834661,
    events_root: None,
}
2023-01-24T10:15:33.892777Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:33.892797Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ABAcalls2"::Berlin::0
2023-01-24T10:15:33.892801Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls2.json"
2023-01-24T10:15:33.892805Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:33.892806Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:34.045170Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031711723,
    events_root: None,
}
2023-01-24T10:15:34.054867Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:34.054889Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ABAcalls2"::London::0
2023-01-24T10:15:34.054892Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls2.json"
2023-01-24T10:15:34.054895Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:34.054897Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:34.197154Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031712183,
    events_root: None,
}
2023-01-24T10:15:34.204708Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:34.204731Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ABAcalls2"::Merge::0
2023-01-24T10:15:34.204734Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls2.json"
2023-01-24T10:15:34.204737Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:34.204739Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:34.346970Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031712183,
    events_root: None,
}
2023-01-24T10:15:34.368297Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls2.json"
2023-01-24T10:15:34.368338Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls3.json"
2023-01-24T10:15:34.392769Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:34.392872Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:34.392876Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:34.392928Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:34.392930Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:15:34.392989Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:34.393060Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:34.393065Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ABAcalls3"::Istanbul::0
2023-01-24T10:15:34.393068Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls3.json"
2023-01-24T10:15:34.393071Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:34.393073Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:34.897907Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3034834661,
    events_root: None,
}
2023-01-24T10:15:34.905229Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:34.905245Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ABAcalls3"::Berlin::0
2023-01-24T10:15:34.905248Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls3.json"
2023-01-24T10:15:34.905252Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:34.905253Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:35.042241Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031711723,
    events_root: None,
}
2023-01-24T10:15:35.051066Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:35.051088Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ABAcalls3"::London::0
2023-01-24T10:15:35.051091Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls3.json"
2023-01-24T10:15:35.051095Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:35.051096Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:35.189605Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031712183,
    events_root: None,
}
2023-01-24T10:15:35.197214Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:35.197244Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ABAcalls3"::Merge::0
2023-01-24T10:15:35.197248Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls3.json"
2023-01-24T10:15:35.197252Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:35.197254Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:35.337614Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3031712183,
    events_root: None,
}
2023-01-24T10:15:35.358966Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcalls3.json"
2023-01-24T10:15:35.359013Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcallsSuicide0.json"
2023-01-24T10:15:35.383319Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:35.383426Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:35.383430Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:35.383484Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:35.383487Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:15:35.383547Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:35.383619Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:35.383624Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ABAcallsSuicide0"::Istanbul::0
2023-01-24T10:15:35.383626Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcallsSuicide0.json"
2023-01-24T10:15:35.383630Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:35.383631Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:35.732336Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2631129,
    events_root: None,
}
2023-01-24T10:15:35.732361Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:35.732367Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ABAcallsSuicide0"::Berlin::0
2023-01-24T10:15:35.732370Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcallsSuicide0.json"
2023-01-24T10:15:35.732373Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:35.732374Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:35.732460Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-24T10:15:35.732466Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:35.732468Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ABAcallsSuicide0"::London::0
2023-01-24T10:15:35.732470Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcallsSuicide0.json"
2023-01-24T10:15:35.732472Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:35.732474Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:35.732542Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-24T10:15:35.732548Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:35.732550Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ABAcallsSuicide0"::Merge::0
2023-01-24T10:15:35.732552Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcallsSuicide0.json"
2023-01-24T10:15:35.732554Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:35.732555Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:35.732622Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-24T10:15:35.733313Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcallsSuicide0.json"
2023-01-24T10:15:35.733342Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcallsSuicide1.json"
2023-01-24T10:15:35.757691Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:35.757793Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:35.757797Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:35.757859Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:35.757862Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:15:35.757920Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:35.757990Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:35.757995Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ABAcallsSuicide1"::Istanbul::0
2023-01-24T10:15:35.757997Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcallsSuicide1.json"
2023-01-24T10:15:35.758001Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:15:35.758002Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:36.104091Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1831187,
    events_root: None,
}
2023-01-24T10:15:36.104114Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 1
2023-01-24T10:15:36.104121Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ABAcallsSuicide1"::Istanbul::1
2023-01-24T10:15:36.104123Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcallsSuicide1.json"
2023-01-24T10:15:36.104126Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:15:36.104128Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:36.104266Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2027795,
    events_root: None,
}
2023-01-24T10:15:36.104275Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:36.104277Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ABAcallsSuicide1"::Berlin::0
2023-01-24T10:15:36.104279Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcallsSuicide1.json"
2023-01-24T10:15:36.104282Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:15:36.104283Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:36.104398Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1831187,
    events_root: None,
}
2023-01-24T10:15:36.104406Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 1
2023-01-24T10:15:36.104409Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ABAcallsSuicide1"::Berlin::1
2023-01-24T10:15:36.104410Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcallsSuicide1.json"
2023-01-24T10:15:36.104413Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:15:36.104415Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:36.104529Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2027795,
    events_root: None,
}
2023-01-24T10:15:36.104536Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:36.104539Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ABAcallsSuicide1"::London::0
2023-01-24T10:15:36.104541Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcallsSuicide1.json"
2023-01-24T10:15:36.104544Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:15:36.104545Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:36.104660Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1831187,
    events_root: None,
}
2023-01-24T10:15:36.104668Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 1
2023-01-24T10:15:36.104670Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ABAcallsSuicide1"::London::1
2023-01-24T10:15:36.104673Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcallsSuicide1.json"
2023-01-24T10:15:36.104675Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:15:36.104676Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:36.104790Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2027795,
    events_root: None,
}
2023-01-24T10:15:36.104797Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:36.104800Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ABAcallsSuicide1"::Merge::0
2023-01-24T10:15:36.104802Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcallsSuicide1.json"
2023-01-24T10:15:36.104804Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:15:36.104806Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:36.104919Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1831187,
    events_root: None,
}
2023-01-24T10:15:36.104926Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 1
2023-01-24T10:15:36.104929Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "ABAcallsSuicide1"::Merge::1
2023-01-24T10:15:36.104931Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcallsSuicide1.json"
2023-01-24T10:15:36.104933Z  INFO evm_eth_compliance::statetest::runner: TX len : 32
2023-01-24T10:15:36.104935Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:36.105051Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2027795,
    events_root: None,
}
2023-01-24T10:15:36.105703Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/ABAcallsSuicide1.json"
2023-01-24T10:15:36.105736Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/Call10.json"
2023-01-24T10:15:36.129528Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:36.129635Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:36.129638Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:36.129686Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:36.129688Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:15:36.129743Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:36.129814Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:36.129819Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call10"::Istanbul::0
2023-01-24T10:15:36.129821Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/Call10.json"
2023-01-24T10:15:36.129825Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:36.129826Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:36.467566Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 25719303,
    events_root: None,
}
2023-01-24T10:15:36.467616Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:36.467623Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call10"::Berlin::0
2023-01-24T10:15:36.467626Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/Call10.json"
2023-01-24T10:15:36.467629Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:36.467631Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:36.468912Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 24281190,
    events_root: None,
}
2023-01-24T10:15:36.468946Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:36.468949Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call10"::London::0
2023-01-24T10:15:36.468951Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/Call10.json"
2023-01-24T10:15:36.468954Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:36.468955Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:36.470212Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 24281190,
    events_root: None,
}
2023-01-24T10:15:36.470246Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:36.470249Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "Call10"::Merge::0
2023-01-24T10:15:36.470251Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/Call10.json"
2023-01-24T10:15:36.470253Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:36.470255Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:36.471509Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 24281190,
    events_root: None,
}
2023-01-24T10:15:36.472184Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/Call10.json"
2023-01-24T10:15:36.472209Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb0.json"
2023-01-24T10:15:36.495441Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:36.495539Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:36.495543Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:36.495594Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:36.495596Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:15:36.495652Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:36.495729Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:36.495734Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallRecursiveBomb0"::Istanbul::0
2023-01-24T10:15:36.495737Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb0.json"
2023-01-24T10:15:36.495739Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:36.495741Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:36.859969Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-01-24T10:15:36.860094Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:36.860101Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallRecursiveBomb0"::Berlin::0
2023-01-24T10:15:36.860103Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb0.json"
2023-01-24T10:15:36.860108Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:36.860109Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:36.863989Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-01-24T10:15:36.864106Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:36.864110Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallRecursiveBomb0"::London::0
2023-01-24T10:15:36.864112Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb0.json"
2023-01-24T10:15:36.864114Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:36.864116Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:36.867976Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-01-24T10:15:36.868093Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:36.868096Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallRecursiveBomb0"::Merge::0
2023-01-24T10:15:36.868098Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb0.json"
2023-01-24T10:15:36.868101Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:36.868102Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:36.871960Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-01-24T10:15:36.873250Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb0.json"
2023-01-24T10:15:36.873277Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb0_OOG_atMaxCallDepth.json"
2023-01-24T10:15:36.896697Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:36.896798Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:36.896801Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:36.896855Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:36.896925Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:36.896930Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallRecursiveBomb0_OOG_atMaxCallDepth"::Istanbul::0
2023-01-24T10:15:36.896933Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb0_OOG_atMaxCallDepth.json"
2023-01-24T10:15:36.896937Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:36.896938Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:37.400165Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3403480531,
    events_root: None,
}
2023-01-24T10:15:37.407477Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:37.407492Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallRecursiveBomb0_OOG_atMaxCallDepth"::Berlin::0
2023-01-24T10:15:37.407495Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb0_OOG_atMaxCallDepth.json"
2023-01-24T10:15:37.407499Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:37.407501Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:37.408090Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 6916483,
    events_root: None,
}
2023-01-24T10:15:37.408104Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:37.408107Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallRecursiveBomb0_OOG_atMaxCallDepth"::London::0
2023-01-24T10:15:37.408109Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb0_OOG_atMaxCallDepth.json"
2023-01-24T10:15:37.408112Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:37.408114Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:37.408240Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1839871,
    events_root: None,
}
2023-01-24T10:15:37.408246Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=64): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:37.408258Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:37.408261Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallRecursiveBomb0_OOG_atMaxCallDepth"::Merge::0
2023-01-24T10:15:37.408263Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb0_OOG_atMaxCallDepth.json"
2023-01-24T10:15:37.408266Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:37.408268Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:37.408378Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1839871,
    events_root: None,
}
2023-01-24T10:15:37.408383Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=64): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:37.420175Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb0_OOG_atMaxCallDepth.json"
2023-01-24T10:15:37.420219Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb1.json"
2023-01-24T10:15:37.443860Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:37.443964Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:37.443967Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:37.444020Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:37.444091Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:37.444095Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallRecursiveBomb1"::Istanbul::0
2023-01-24T10:15:37.444098Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb1.json"
2023-01-24T10:15:37.444101Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:37.444102Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:37.930593Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3368215765,
    events_root: None,
}
2023-01-24T10:15:37.938023Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:37.938041Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallRecursiveBomb1"::Berlin::0
2023-01-24T10:15:37.938045Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb1.json"
2023-01-24T10:15:37.938048Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:37.938050Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:38.120221Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4306107212,
    events_root: None,
}
2023-01-24T10:15:38.126327Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:38.126345Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallRecursiveBomb1"::London::0
2023-01-24T10:15:38.126348Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb1.json"
2023-01-24T10:15:38.126352Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:38.126353Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:38.300802Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4306106936,
    events_root: None,
}
2023-01-24T10:15:38.305810Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:38.305825Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallRecursiveBomb1"::Merge::0
2023-01-24T10:15:38.305828Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb1.json"
2023-01-24T10:15:38.305832Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:38.305833Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:38.471806Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4306107120,
    events_root: None,
}
2023-01-24T10:15:38.493534Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb1.json"
2023-01-24T10:15:38.493581Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb2.json"
2023-01-24T10:15:38.516835Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:38.516935Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:38.516939Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:38.516992Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:38.517062Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:38.517067Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallRecursiveBomb2"::Istanbul::0
2023-01-24T10:15:38.517069Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb2.json"
2023-01-24T10:15:38.517073Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:38.517074Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:39.028343Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3368215765,
    events_root: None,
}
2023-01-24T10:15:39.036122Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:39.036141Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallRecursiveBomb2"::Berlin::0
2023-01-24T10:15:39.036145Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb2.json"
2023-01-24T10:15:39.036148Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:39.036150Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:39.215751Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4306107212,
    events_root: None,
}
2023-01-24T10:15:39.221066Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:39.221086Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallRecursiveBomb2"::London::0
2023-01-24T10:15:39.221089Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb2.json"
2023-01-24T10:15:39.221093Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:39.221095Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:39.395915Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4306106936,
    events_root: None,
}
2023-01-24T10:15:39.400984Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:39.400998Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallRecursiveBomb2"::Merge::0
2023-01-24T10:15:39.401001Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb2.json"
2023-01-24T10:15:39.401005Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:39.401006Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:39.578943Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4306107120,
    events_root: None,
}
2023-01-24T10:15:39.601397Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb2.json"
2023-01-24T10:15:39.601440Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb3.json"
2023-01-24T10:15:39.626248Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:39.626354Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:39.626357Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:39.626418Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:39.626490Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:39.626494Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallRecursiveBomb3"::Istanbul::0
2023-01-24T10:15:39.626497Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb3.json"
2023-01-24T10:15:39.626500Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:39.626502Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:40.122712Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3368114727,
    events_root: None,
}
2023-01-24T10:15:40.130867Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:40.130884Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallRecursiveBomb3"::Berlin::0
2023-01-24T10:15:40.130888Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb3.json"
2023-01-24T10:15:40.130892Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:40.130894Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:40.313086Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4306006359,
    events_root: None,
}
2023-01-24T10:15:40.318358Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:40.318381Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallRecursiveBomb3"::London::0
2023-01-24T10:15:40.318384Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb3.json"
2023-01-24T10:15:40.318388Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:40.318390Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:40.500679Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4306006451,
    events_root: None,
}
2023-01-24T10:15:40.505889Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:40.505906Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallRecursiveBomb3"::Merge::0
2023-01-24T10:15:40.505909Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb3.json"
2023-01-24T10:15:40.505913Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:40.505915Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:40.688611Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4306006267,
    events_root: None,
}
2023-01-24T10:15:40.716213Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBomb3.json"
2023-01-24T10:15:40.716257Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBombLog.json"
2023-01-24T10:15:40.740714Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:40.740821Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:40.740824Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:40.740881Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:40.740884Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:15:40.740944Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:40.741016Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:40.741021Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallRecursiveBombLog"::Istanbul::0
2023-01-24T10:15:40.741024Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBombLog.json"
2023-01-24T10:15:40.741027Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:40.741029Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:41.131110Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-01-24T10:15:41.131269Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:41.131280Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallRecursiveBombLog"::Berlin::0
2023-01-24T10:15:41.131284Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBombLog.json"
2023-01-24T10:15:41.131289Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:41.131290Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:41.136309Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-01-24T10:15:41.136452Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:41.136459Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallRecursiveBombLog"::London::0
2023-01-24T10:15:41.136461Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBombLog.json"
2023-01-24T10:15:41.136465Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:41.136466Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:41.141113Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-01-24T10:15:41.141244Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:41.141249Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallRecursiveBombLog"::Merge::0
2023-01-24T10:15:41.141251Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBombLog.json"
2023-01-24T10:15:41.141254Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:41.141256Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:41.145778Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-01-24T10:15:41.147225Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBombLog.json"
2023-01-24T10:15:41.147257Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBombLog2.json"
2023-01-24T10:15:41.171878Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:41.171993Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:41.171998Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:41.172067Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:41.172071Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:15:41.172146Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:41.172235Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:41.172244Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallRecursiveBombLog2"::Istanbul::0
2023-01-24T10:15:41.172247Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBombLog2.json"
2023-01-24T10:15:41.172251Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:41.172253Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:41.544594Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-01-24T10:15:41.544731Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:41.544738Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallRecursiveBombLog2"::Berlin::0
2023-01-24T10:15:41.544741Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBombLog2.json"
2023-01-24T10:15:41.544744Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:41.544745Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:41.549063Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-01-24T10:15:41.549192Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:41.549196Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallRecursiveBombLog2"::London::0
2023-01-24T10:15:41.549198Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBombLog2.json"
2023-01-24T10:15:41.549201Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:41.549202Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:41.553462Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-01-24T10:15:41.553592Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:41.553596Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallRecursiveBombLog2"::Merge::0
2023-01-24T10:15:41.553598Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBombLog2.json"
2023-01-24T10:15:41.553601Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:41.553602Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:41.557891Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 101706651,
    events_root: None,
}
2023-01-24T10:15:41.559296Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallRecursiveBombLog2.json"
2023-01-24T10:15:41.559326Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistrator0.json"
2023-01-24T10:15:41.583781Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:41.583887Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:41.583890Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:41.583944Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:41.583946Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:15:41.584007Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:41.584079Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:41.584084Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistrator0"::Istanbul::0
2023-01-24T10:15:41.584086Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistrator0.json"
2023-01-24T10:15:41.584090Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:41.584091Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:41.928100Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1837523,
    events_root: None,
}
2023-01-24T10:15:41.928125Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:41.928132Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistrator0"::Berlin::0
2023-01-24T10:15:41.928134Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistrator0.json"
2023-01-24T10:15:41.928138Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:41.928140Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:41.928273Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1837523,
    events_root: None,
}
2023-01-24T10:15:41.928280Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:41.928283Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistrator0"::London::0
2023-01-24T10:15:41.928285Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistrator0.json"
2023-01-24T10:15:41.928288Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:41.928289Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:41.928405Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1837523,
    events_root: None,
}
2023-01-24T10:15:41.928413Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:41.928415Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistrator0"::Merge::0
2023-01-24T10:15:41.928418Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistrator0.json"
2023-01-24T10:15:41.928420Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:41.928422Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:41.928556Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1837523,
    events_root: None,
}
2023-01-24T10:15:41.929210Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistrator0.json"
2023-01-24T10:15:41.929239Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorAddressTooBigLeft.json"
2023-01-24T10:15:41.953739Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:41.953842Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:41.953846Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:41.953900Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:41.953902Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:15:41.953960Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:41.954031Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:41.954036Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorAddressTooBigLeft"::Istanbul::0
2023-01-24T10:15:41.954039Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorAddressTooBigLeft.json"
2023-01-24T10:15:41.954042Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:41.954044Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:42.304049Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1738543,
    events_root: None,
}
2023-01-24T10:15:42.304075Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:42.304084Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorAddressTooBigLeft"::Berlin::0
2023-01-24T10:15:42.304087Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorAddressTooBigLeft.json"
2023-01-24T10:15:42.304091Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:42.304093Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:42.304272Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1738543,
    events_root: None,
}
2023-01-24T10:15:42.304282Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:42.304285Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorAddressTooBigLeft"::London::0
2023-01-24T10:15:42.304288Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorAddressTooBigLeft.json"
2023-01-24T10:15:42.304291Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:42.304293Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:42.304462Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1738543,
    events_root: None,
}
2023-01-24T10:15:42.304472Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:42.304475Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorAddressTooBigLeft"::Merge::0
2023-01-24T10:15:42.304478Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorAddressTooBigLeft.json"
2023-01-24T10:15:42.304482Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:42.304483Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:42.304622Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1738543,
    events_root: None,
}
2023-01-24T10:15:42.305414Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorAddressTooBigLeft.json"
2023-01-24T10:15:42.305448Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorAddressTooBigRight.json"
2023-01-24T10:15:42.330654Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:42.330758Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:42.330761Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:42.330814Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:42.330817Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:15:42.330878Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:42.330951Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:42.330956Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorAddressTooBigRight"::Istanbul::0
2023-01-24T10:15:42.330960Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorAddressTooBigRight.json"
2023-01-24T10:15:42.330964Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:42.330965Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:42.709999Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 4006546,
    events_root: None,
}
2023-01-24T10:15:42.710023Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:42.710030Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorAddressTooBigRight"::Berlin::0
2023-01-24T10:15:42.710034Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorAddressTooBigRight.json"
2023-01-24T10:15:42.710037Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:42.710038Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:42.710193Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1940504,
    events_root: None,
}
2023-01-24T10:15:42.710201Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:42.710204Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorAddressTooBigRight"::London::0
2023-01-24T10:15:42.710207Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorAddressTooBigRight.json"
2023-01-24T10:15:42.710210Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:42.710211Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:42.710323Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1940504,
    events_root: None,
}
2023-01-24T10:15:42.710331Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:42.710334Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorAddressTooBigRight"::Merge::0
2023-01-24T10:15:42.710336Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorAddressTooBigRight.json"
2023-01-24T10:15:42.710339Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:42.710341Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:42.710451Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1940504,
    events_root: None,
}
2023-01-24T10:15:42.711198Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorAddressTooBigRight.json"
2023-01-24T10:15:42.711226Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorMemOOGAndInsufficientBalance.json"
2023-01-24T10:15:42.735622Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:42.735732Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:42.735735Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:42.735789Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:42.735791Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:15:42.735849Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:42.735921Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:42.735925Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorMemOOGAndInsufficientBalance"::Istanbul::0
2023-01-24T10:15:42.735929Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorMemOOGAndInsufficientBalance.json"
2023-01-24T10:15:42.735932Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:42.735933Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:43.078716Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1555423,
    events_root: None,
}
2023-01-24T10:15:43.078736Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=114): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:43.078751Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:43.078759Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorMemOOGAndInsufficientBalance"::Berlin::0
2023-01-24T10:15:43.078762Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorMemOOGAndInsufficientBalance.json"
2023-01-24T10:15:43.078766Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:43.078767Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:43.078899Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1555423,
    events_root: None,
}
2023-01-24T10:15:43.078905Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=114): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:43.078913Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:43.078916Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorMemOOGAndInsufficientBalance"::London::0
2023-01-24T10:15:43.078918Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorMemOOGAndInsufficientBalance.json"
2023-01-24T10:15:43.078921Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:43.078922Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:43.079008Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1555423,
    events_root: None,
}
2023-01-24T10:15:43.079013Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=114): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:43.079022Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:43.079024Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorMemOOGAndInsufficientBalance"::Merge::0
2023-01-24T10:15:43.079026Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorMemOOGAndInsufficientBalance.json"
2023-01-24T10:15:43.079029Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:43.079030Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:43.079116Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1555423,
    events_root: None,
}
2023-01-24T10:15:43.079121Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=114): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:43.079990Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorMemOOGAndInsufficientBalance.json"
2023-01-24T10:15:43.080027Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorNotMuchMemory0.json"
2023-01-24T10:15:43.104262Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:43.104397Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:43.104403Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:43.104478Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:43.104482Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:15:43.104563Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:43.104655Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:43.104661Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorNotMuchMemory0"::Istanbul::0
2023-01-24T10:15:43.104664Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorNotMuchMemory0.json"
2023-01-24T10:15:43.104668Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:43.104669Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:43.490247Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1738138,
    events_root: None,
}
2023-01-24T10:15:43.490271Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:43.490277Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorNotMuchMemory0"::Berlin::0
2023-01-24T10:15:43.490280Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorNotMuchMemory0.json"
2023-01-24T10:15:43.490284Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:43.490286Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:43.490433Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1738138,
    events_root: None,
}
2023-01-24T10:15:43.490441Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:43.490444Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorNotMuchMemory0"::London::0
2023-01-24T10:15:43.490447Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorNotMuchMemory0.json"
2023-01-24T10:15:43.490449Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:43.490450Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:43.490567Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1738138,
    events_root: None,
}
2023-01-24T10:15:43.490574Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:43.490577Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorNotMuchMemory0"::Merge::0
2023-01-24T10:15:43.490579Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorNotMuchMemory0.json"
2023-01-24T10:15:43.490582Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:43.490583Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:43.490698Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1738138,
    events_root: None,
}
2023-01-24T10:15:43.491361Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorNotMuchMemory0.json"
2023-01-24T10:15:43.491392Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorNotMuchMemory1.json"
2023-01-24T10:15:43.515834Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:43.515937Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:43.515940Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:43.516005Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:43.516008Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:15:43.516069Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:43.516141Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:43.516146Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorNotMuchMemory1"::Istanbul::0
2023-01-24T10:15:43.516149Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorNotMuchMemory1.json"
2023-01-24T10:15:43.516152Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:43.516153Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:43.891810Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1721044,
    events_root: None,
}
2023-01-24T10:15:43.891833Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:43.891839Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorNotMuchMemory1"::Berlin::0
2023-01-24T10:15:43.891842Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorNotMuchMemory1.json"
2023-01-24T10:15:43.891845Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:43.891847Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:43.891970Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1721044,
    events_root: None,
}
2023-01-24T10:15:43.891978Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:43.891981Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorNotMuchMemory1"::London::0
2023-01-24T10:15:43.891983Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorNotMuchMemory1.json"
2023-01-24T10:15:43.891986Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:43.891988Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:43.892100Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1721044,
    events_root: None,
}
2023-01-24T10:15:43.892108Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:43.892111Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorNotMuchMemory1"::Merge::0
2023-01-24T10:15:43.892113Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorNotMuchMemory1.json"
2023-01-24T10:15:43.892117Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:43.892118Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:43.892226Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1721044,
    events_root: None,
}
2023-01-24T10:15:43.892985Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorNotMuchMemory1.json"
2023-01-24T10:15:43.893013Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorOutOfGas.json"
2023-01-24T10:15:43.917605Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:43.917733Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:43.917738Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:43.917794Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:43.917796Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:15:43.917855Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:43.917927Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:43.917933Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorOutOfGas"::Istanbul::0
2023-01-24T10:15:43.917936Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorOutOfGas.json"
2023-01-24T10:15:43.917940Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:43.917941Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:44.273421Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1737591,
    events_root: None,
}
2023-01-24T10:15:44.273446Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:44.273452Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorOutOfGas"::Berlin::0
2023-01-24T10:15:44.273455Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorOutOfGas.json"
2023-01-24T10:15:44.273458Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:44.273459Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:44.273670Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1737591,
    events_root: None,
}
2023-01-24T10:15:44.273681Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:44.273685Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorOutOfGas"::London::0
2023-01-24T10:15:44.273688Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorOutOfGas.json"
2023-01-24T10:15:44.273692Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:44.273694Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:44.273821Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1737591,
    events_root: None,
}
2023-01-24T10:15:44.273830Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:44.273832Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorOutOfGas"::Merge::0
2023-01-24T10:15:44.273834Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorOutOfGas.json"
2023-01-24T10:15:44.273837Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:44.273839Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:44.273950Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1737591,
    events_root: None,
}
2023-01-24T10:15:44.274706Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorOutOfGas.json"
2023-01-24T10:15:44.274732Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory0.json"
2023-01-24T10:15:44.298890Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:44.298992Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:44.298995Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:44.299046Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:44.299048Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:15:44.299106Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:44.299176Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:44.299180Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorTooMuchMemory0"::Istanbul::0
2023-01-24T10:15:44.299183Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory0.json"
2023-01-24T10:15:44.299186Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:44.299187Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:44.686974Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 396594357,
    events_root: None,
}
2023-01-24T10:15:44.686991Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:44.687004Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:44.687011Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorTooMuchMemory0"::Berlin::0
2023-01-24T10:15:44.687013Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory0.json"
2023-01-24T10:15:44.687016Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:44.687018Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:44.687122Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 396594357,
    events_root: None,
}
2023-01-24T10:15:44.687127Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:44.687136Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:44.687138Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorTooMuchMemory0"::London::0
2023-01-24T10:15:44.687140Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory0.json"
2023-01-24T10:15:44.687143Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:44.687145Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:44.687229Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 396594357,
    events_root: None,
}
2023-01-24T10:15:44.687234Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:44.687242Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:44.687244Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorTooMuchMemory0"::Merge::0
2023-01-24T10:15:44.687246Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory0.json"
2023-01-24T10:15:44.687249Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:44.687251Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:44.687360Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 4,
    },
    return_data: RawBytes {  },
    gas_used: 396594357,
    events_root: None,
}
2023-01-24T10:15:44.687366Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 4,
                    },
                    message: "wasm `unreachable` instruction executed",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:44.688144Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory0.json"
2023-01-24T10:15:44.688171Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory1.json"
2023-01-24T10:15:44.712269Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:44.712375Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:44.712378Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:44.712431Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:44.712432Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:15:44.712490Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:44.712561Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:44.712566Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorTooMuchMemory1"::Istanbul::0
2023-01-24T10:15:44.712569Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory1.json"
2023-01-24T10:15:44.712572Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:44.712574Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:45.095792Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17561259,
    events_root: None,
}
2023-01-24T10:15:45.095824Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:45.095832Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorTooMuchMemory1"::Berlin::0
2023-01-24T10:15:45.095836Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory1.json"
2023-01-24T10:15:45.095840Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:45.095841Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:45.101810Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17561259,
    events_root: None,
}
2023-01-24T10:15:45.101840Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:45.101847Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorTooMuchMemory1"::London::0
2023-01-24T10:15:45.101850Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory1.json"
2023-01-24T10:15:45.101853Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:45.101854Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:45.107459Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17561259,
    events_root: None,
}
2023-01-24T10:15:45.107483Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:45.107490Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorTooMuchMemory1"::Merge::0
2023-01-24T10:15:45.107493Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory1.json"
2023-01-24T10:15:45.107497Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:45.107498Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:45.112896Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 17561259,
    events_root: None,
}
2023-01-24T10:15:45.113727Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory1.json"
2023-01-24T10:15:45.113757Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory2.json"
2023-01-24T10:15:45.139281Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:45.139392Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:45.139396Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:45.139454Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:45.139457Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:15:45.139523Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:45.139599Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:45.139606Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorTooMuchMemory2"::Istanbul::0
2023-01-24T10:15:45.139610Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory2.json"
2023-01-24T10:15:45.139614Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:45.139616Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:45.474810Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2622591,
    events_root: None,
}
2023-01-24T10:15:45.474832Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:45.474839Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorTooMuchMemory2"::Berlin::0
2023-01-24T10:15:45.474842Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory2.json"
2023-01-24T10:15:45.474845Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:45.474846Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:45.475157Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2622591,
    events_root: None,
}
2023-01-24T10:15:45.475165Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:45.475168Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorTooMuchMemory2"::London::0
2023-01-24T10:15:45.475170Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory2.json"
2023-01-24T10:15:45.475173Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:45.475174Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:45.475465Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2622591,
    events_root: None,
}
2023-01-24T10:15:45.475473Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:45.475476Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorTooMuchMemory2"::Merge::0
2023-01-24T10:15:45.475478Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory2.json"
2023-01-24T10:15:45.475481Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:45.475482Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:45.475782Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2622591,
    events_root: None,
}
2023-01-24T10:15:45.476543Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorTooMuchMemory2.json"
2023-01-24T10:15:45.476574Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorZeorSizeMemExpansion.json"
2023-01-24T10:15:45.501665Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:45.501770Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:45.501773Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:45.501826Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:45.501828Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:15:45.501888Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:45.501958Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:45.501963Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::Istanbul::0
2023-01-24T10:15:45.501966Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorZeorSizeMemExpansion.json"
2023-01-24T10:15:45.501969Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:45.501971Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:45.851933Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1725495,
    events_root: None,
}
2023-01-24T10:15:45.851956Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:45.851962Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::Istanbul::0
2023-01-24T10:15:45.851965Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorZeorSizeMemExpansion.json"
2023-01-24T10:15:45.851968Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:45.851970Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:45.852094Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1725495,
    events_root: None,
}
2023-01-24T10:15:45.852102Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:45.852105Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::Berlin::0
2023-01-24T10:15:45.852107Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorZeorSizeMemExpansion.json"
2023-01-24T10:15:45.852110Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:45.852111Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:45.852222Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1725495,
    events_root: None,
}
2023-01-24T10:15:45.852230Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:45.852232Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::Berlin::0
2023-01-24T10:15:45.852234Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorZeorSizeMemExpansion.json"
2023-01-24T10:15:45.852237Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:45.852239Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:45.852347Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1725495,
    events_root: None,
}
2023-01-24T10:15:45.852355Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:45.852357Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::London::0
2023-01-24T10:15:45.852359Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorZeorSizeMemExpansion.json"
2023-01-24T10:15:45.852362Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:45.852364Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:45.852472Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1725495,
    events_root: None,
}
2023-01-24T10:15:45.852479Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:45.852481Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::London::0
2023-01-24T10:15:45.852483Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorZeorSizeMemExpansion.json"
2023-01-24T10:15:45.852486Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:45.852488Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:45.852596Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1725495,
    events_root: None,
}
2023-01-24T10:15:45.852603Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:45.852606Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::Merge::0
2023-01-24T10:15:45.852608Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorZeorSizeMemExpansion.json"
2023-01-24T10:15:45.852611Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:45.852613Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:45.852720Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1725495,
    events_root: None,
}
2023-01-24T10:15:45.852728Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:45.852731Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToNameRegistratorZeorSizeMemExpansion"::Merge::0
2023-01-24T10:15:45.852733Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorZeorSizeMemExpansion.json"
2023-01-24T10:15:45.852736Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:45.852737Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:45.852843Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1725495,
    events_root: None,
}
2023-01-24T10:15:45.853465Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToNameRegistratorZeorSizeMemExpansion.json"
2023-01-24T10:15:45.853497Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1.json"
2023-01-24T10:15:45.877881Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:45.877982Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:45.877986Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:45.878040Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:45.878042Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:15:45.878101Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:45.878172Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:45.878177Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToReturn1"::Istanbul::0
2023-01-24T10:15:45.878180Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1.json"
2023-01-24T10:15:45.878183Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:45.878184Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:46.245096Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1718445,
    events_root: None,
}
2023-01-24T10:15:46.245120Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:46.245127Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToReturn1"::Berlin::0
2023-01-24T10:15:46.245130Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1.json"
2023-01-24T10:15:46.245134Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:46.245135Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:46.245284Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1718445,
    events_root: None,
}
2023-01-24T10:15:46.245293Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:46.245296Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToReturn1"::London::0
2023-01-24T10:15:46.245299Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1.json"
2023-01-24T10:15:46.245302Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:46.245304Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:46.245422Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1718445,
    events_root: None,
}
2023-01-24T10:15:46.245430Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:46.245433Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToReturn1"::Merge::0
2023-01-24T10:15:46.245436Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1.json"
2023-01-24T10:15:46.245439Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:46.245441Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:46.245553Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1718445,
    events_root: None,
}
2023-01-24T10:15:46.246184Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1.json"
2023-01-24T10:15:46.246212Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1ForDynamicJump0.json"
2023-01-24T10:15:46.270459Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:46.270572Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:46.270576Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:46.270634Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:46.270636Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:15:46.270698Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:46.270772Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:46.270779Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToReturn1ForDynamicJump0"::Istanbul::0
2023-01-24T10:15:46.270782Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1ForDynamicJump0.json"
2023-01-24T10:15:46.270787Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:46.270789Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:46.612086Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1734026,
    events_root: None,
}
2023-01-24T10:15:46.612103Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=41): jumpdest 0 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:46.612120Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:46.612129Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToReturn1ForDynamicJump0"::Berlin::0
2023-01-24T10:15:46.612131Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1ForDynamicJump0.json"
2023-01-24T10:15:46.612135Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:46.612137Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:46.612288Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1734026,
    events_root: None,
}
2023-01-24T10:15:46.612293Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=41): jumpdest 0 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:46.612306Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:46.612310Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToReturn1ForDynamicJump0"::London::0
2023-01-24T10:15:46.612312Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1ForDynamicJump0.json"
2023-01-24T10:15:46.612316Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:46.612318Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:46.612433Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1734026,
    events_root: None,
}
2023-01-24T10:15:46.612438Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=41): jumpdest 0 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:46.612451Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:46.612454Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToReturn1ForDynamicJump0"::Merge::0
2023-01-24T10:15:46.612456Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1ForDynamicJump0.json"
2023-01-24T10:15:46.612459Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:46.612461Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:46.612574Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1734026,
    events_root: None,
}
2023-01-24T10:15:46.612579Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=41): jumpdest 0 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:46.613367Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1ForDynamicJump0.json"
2023-01-24T10:15:46.613395Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1ForDynamicJump1.json"
2023-01-24T10:15:46.640989Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:46.641095Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:46.641099Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:46.641154Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:46.641156Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:15:46.641217Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:46.641296Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:46.641302Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToReturn1ForDynamicJump1"::Istanbul::0
2023-01-24T10:15:46.641305Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1ForDynamicJump1.json"
2023-01-24T10:15:46.641310Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:46.641312Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:46.987517Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1734137,
    events_root: None,
}
2023-01-24T10:15:46.987536Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=41): jumpdest 0 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:46.987551Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:46.987557Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToReturn1ForDynamicJump1"::Berlin::0
2023-01-24T10:15:46.987559Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1ForDynamicJump1.json"
2023-01-24T10:15:46.987563Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:46.987564Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:46.987700Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1734137,
    events_root: None,
}
2023-01-24T10:15:46.987706Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=41): jumpdest 0 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:46.987715Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:46.987718Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToReturn1ForDynamicJump1"::London::0
2023-01-24T10:15:46.987719Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1ForDynamicJump1.json"
2023-01-24T10:15:46.987722Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:46.987724Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:46.987837Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1734137,
    events_root: None,
}
2023-01-24T10:15:46.987842Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=41): jumpdest 0 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:46.987853Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:46.987855Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CallToReturn1ForDynamicJump1"::Merge::0
2023-01-24T10:15:46.987857Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1ForDynamicJump1.json"
2023-01-24T10:15:46.987860Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:46.987861Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:46.987972Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 39,
    },
    return_data: RawBytes {  },
    gas_used: 1734137,
    events_root: None,
}
2023-01-24T10:15:46.987977Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 39,
                    },
                    message: "ABORT(pc=41): jumpdest 0 is invalid",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:46.988755Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CallToReturn1ForDynamicJump1.json"
2023-01-24T10:15:46.988780Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CalltoReturn2.json"
2023-01-24T10:15:47.013873Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:47.013982Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:47.013986Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:47.014039Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:47.014041Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:15:47.014102Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:47.014176Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:47.014181Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CalltoReturn2"::Istanbul::0
2023-01-24T10:15:47.014184Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CalltoReturn2.json"
2023-01-24T10:15:47.014187Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:47.014188Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:47.381607Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1742973,
    events_root: None,
}
2023-01-24T10:15:47.381629Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:47.381635Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CalltoReturn2"::Berlin::0
2023-01-24T10:15:47.381638Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CalltoReturn2.json"
2023-01-24T10:15:47.381641Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:47.381642Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:47.381779Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1742973,
    events_root: None,
}
2023-01-24T10:15:47.381786Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:47.381790Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CalltoReturn2"::London::0
2023-01-24T10:15:47.381792Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CalltoReturn2.json"
2023-01-24T10:15:47.381794Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:47.381796Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:47.381913Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1742973,
    events_root: None,
}
2023-01-24T10:15:47.381921Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:47.381925Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CalltoReturn2"::Merge::0
2023-01-24T10:15:47.381927Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CalltoReturn2.json"
2023-01-24T10:15:47.381929Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:47.381931Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:47.382039Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1742973,
    events_root: None,
}
2023-01-24T10:15:47.382752Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CalltoReturn2.json"
2023-01-24T10:15:47.382781Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CreateHashCollision.json"
2023-01-24T10:15:47.407518Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:47.407623Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:47.407627Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:47.407692Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:47.407695Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:15:47.407758Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:47.407833Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:47.407839Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateHashCollision"::Istanbul::0
2023-01-24T10:15:47.407843Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CreateHashCollision.json"
2023-01-24T10:15:47.407847Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:47.407849Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:47.861548Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3909237,
    events_root: None,
}
2023-01-24T10:15:47.861578Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:47.861584Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateHashCollision"::Berlin::0
2023-01-24T10:15:47.861587Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CreateHashCollision.json"
2023-01-24T10:15:47.861589Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:47.861591Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [184, 141, 232, 139, 53, 236, 191, 60, 20, 30, 60, 170, 226, 186, 243, 88, 52, 209, 143, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-01-24T10:15:48.027204Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13534900,
    events_root: None,
}
2023-01-24T10:15:48.027240Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:48.027249Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateHashCollision"::London::0
2023-01-24T10:15:48.027252Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CreateHashCollision.json"
2023-01-24T10:15:48.027256Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:48.027258Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [93, 53, 72, 12, 110, 127, 137, 82, 54, 63, 162, 128, 160, 169, 105, 6, 218, 152, 31, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-01-24T10:15:48.027916Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14470477,
    events_root: None,
}
2023-01-24T10:15:48.027939Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:48.027943Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "CreateHashCollision"::Merge::0
2023-01-24T10:15:48.027946Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CreateHashCollision.json"
2023-01-24T10:15:48.027950Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:48.027952Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [91, 91, 211, 67, 161, 47, 180, 44, 98, 57, 10, 255, 99, 64, 181, 153, 71, 182, 2, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-01-24T10:15:48.028591Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14988249,
    events_root: None,
}
2023-01-24T10:15:48.029571Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/CreateHashCollision.json"
2023-01-24T10:15:48.029600Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/PostToReturn1.json"
2023-01-24T10:15:48.053981Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:48.054092Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:48.054096Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:48.054153Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:48.054156Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:15:48.054219Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:48.054294Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:48.054300Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "PostToReturn1"::Istanbul::0
2023-01-24T10:15:48.054303Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/PostToReturn1.json"
2023-01-24T10:15:48.054307Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:48.054309Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:48.407261Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2702051,
    events_root: None,
}
2023-01-24T10:15:48.407286Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:48.407293Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "PostToReturn1"::Berlin::0
2023-01-24T10:15:48.407295Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/PostToReturn1.json"
2023-01-24T10:15:48.407299Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:48.407300Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:48.407435Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1803016,
    events_root: None,
}
2023-01-24T10:15:48.407442Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:48.407445Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "PostToReturn1"::London::0
2023-01-24T10:15:48.407447Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/PostToReturn1.json"
2023-01-24T10:15:48.407449Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:48.407451Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:48.407601Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1803016,
    events_root: None,
}
2023-01-24T10:15:48.407610Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:48.407614Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "PostToReturn1"::Merge::0
2023-01-24T10:15:48.407617Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/PostToReturn1.json"
2023-01-24T10:15:48.407620Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:48.407622Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:48.407771Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1803016,
    events_root: None,
}
2023-01-24T10:15:48.408544Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/PostToReturn1.json"
2023-01-24T10:15:48.408573Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/TestNameRegistrator.json"
2023-01-24T10:15:48.432769Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:48.432888Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:48.432891Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:48.432947Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:48.433020Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:48.433026Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "TestNameRegistrator"::Istanbul::0
2023-01-24T10:15:48.433029Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/TestNameRegistrator.json"
2023-01-24T10:15:48.433032Z  INFO evm_eth_compliance::statetest::runner: TX len : 64
2023-01-24T10:15:48.433033Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:48.805860Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2563734,
    events_root: None,
}
2023-01-24T10:15:48.805885Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:48.805892Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "TestNameRegistrator"::Berlin::0
2023-01-24T10:15:48.805895Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/TestNameRegistrator.json"
2023-01-24T10:15:48.805898Z  INFO evm_eth_compliance::statetest::runner: TX len : 64
2023-01-24T10:15:48.805899Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:48.806012Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559399,
    events_root: None,
}
2023-01-24T10:15:48.806020Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:48.806022Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "TestNameRegistrator"::London::0
2023-01-24T10:15:48.806024Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/TestNameRegistrator.json"
2023-01-24T10:15:48.806026Z  INFO evm_eth_compliance::statetest::runner: TX len : 64
2023-01-24T10:15:48.806028Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:48.806119Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559399,
    events_root: None,
}
2023-01-24T10:15:48.806143Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:48.806152Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "TestNameRegistrator"::Merge::0
2023-01-24T10:15:48.806160Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/TestNameRegistrator.json"
2023-01-24T10:15:48.806168Z  INFO evm_eth_compliance::statetest::runner: TX len : 64
2023-01-24T10:15:48.806176Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:48.806303Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1559399,
    events_root: None,
}
2023-01-24T10:15:48.807356Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/TestNameRegistrator.json"
2023-01-24T10:15:48.807389Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/balanceInputAddressTooBig.json"
2023-01-24T10:15:48.833659Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:48.833766Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:48.833769Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:48.833824Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:48.833899Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:48.833904Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "balanceInputAddressTooBig"::Istanbul::0
2023-01-24T10:15:48.833906Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/balanceInputAddressTooBig.json"
2023-01-24T10:15:48.833910Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:48.833911Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:49.192419Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1554776,
    events_root: None,
}
2023-01-24T10:15:49.192439Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:49.192446Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "balanceInputAddressTooBig"::Berlin::0
2023-01-24T10:15:49.192449Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/balanceInputAddressTooBig.json"
2023-01-24T10:15:49.192453Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:49.192454Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:49.192573Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1554776,
    events_root: None,
}
2023-01-24T10:15:49.192581Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:49.192583Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "balanceInputAddressTooBig"::London::0
2023-01-24T10:15:49.192585Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/balanceInputAddressTooBig.json"
2023-01-24T10:15:49.192588Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:49.192589Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:49.192691Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1554776,
    events_root: None,
}
2023-01-24T10:15:49.192699Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:49.192702Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "balanceInputAddressTooBig"::Merge::0
2023-01-24T10:15:49.192704Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/balanceInputAddressTooBig.json"
2023-01-24T10:15:49.192707Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:49.192708Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:49.192808Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1554776,
    events_root: None,
}
2023-01-24T10:15:49.193437Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/balanceInputAddressTooBig.json"
2023-01-24T10:15:49.193463Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callValue.json"
2023-01-24T10:15:49.217446Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:49.217553Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:49.217557Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:49.217613Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:49.217686Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:49.217691Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callValue"::Istanbul::0
2023-01-24T10:15:49.217694Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callValue.json"
2023-01-24T10:15:49.217697Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:49.217699Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:49.562048Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529858,
    events_root: None,
}
2023-01-24T10:15:49.562070Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:49.562076Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callValue"::Berlin::0
2023-01-24T10:15:49.562079Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callValue.json"
2023-01-24T10:15:49.562082Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:49.562083Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:49.562202Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529858,
    events_root: None,
}
2023-01-24T10:15:49.562209Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:49.562212Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callValue"::London::0
2023-01-24T10:15:49.562214Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callValue.json"
2023-01-24T10:15:49.562216Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:49.562218Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:49.562303Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529858,
    events_root: None,
}
2023-01-24T10:15:49.562309Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:49.562312Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callValue"::Merge::0
2023-01-24T10:15:49.562314Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callValue.json"
2023-01-24T10:15:49.562317Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:49.562318Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:49.562400Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1529858,
    events_root: None,
}
2023-01-24T10:15:49.563015Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callValue.json"
2023-01-24T10:15:49.563046Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeTo0.json"
2023-01-24T10:15:49.587768Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:49.587872Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:49.587876Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:49.587931Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:49.588004Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:49.588009Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeTo0"::Istanbul::0
2023-01-24T10:15:49.588013Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeTo0.json"
2023-01-24T10:15:49.588016Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:49.588017Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:49.957310Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1542571,
    events_root: None,
}
2023-01-24T10:15:49.957328Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=15): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:49.957343Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:49.957349Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeTo0"::Berlin::0
2023-01-24T10:15:49.957351Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeTo0.json"
2023-01-24T10:15:49.957354Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:49.957355Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:49.957459Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1542571,
    events_root: None,
}
2023-01-24T10:15:49.957464Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=15): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:49.957472Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:49.957475Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeTo0"::London::0
2023-01-24T10:15:49.957477Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeTo0.json"
2023-01-24T10:15:49.957480Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:49.957481Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:49.957568Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1542571,
    events_root: None,
}
2023-01-24T10:15:49.957573Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=15): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:49.957582Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:49.957585Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeTo0"::Merge::0
2023-01-24T10:15:49.957586Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeTo0.json"
2023-01-24T10:15:49.957589Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:49.957590Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:49.957681Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1542571,
    events_root: None,
}
2023-01-24T10:15:49.957686Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=15): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:49.958348Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeTo0.json"
2023-01-24T10:15:49.958377Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistrator0.json"
2023-01-24T10:15:49.983045Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:49.983158Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:49.983161Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:49.983231Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:49.983234Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:15:49.983317Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:49.983428Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:49.983434Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeToNameRegistrator0"::Istanbul::0
2023-01-24T10:15:49.983437Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistrator0.json"
2023-01-24T10:15:49.983441Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:49.983442Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:50.326595Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-01-24T10:15:50.326615Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=106): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:50.326630Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:50.326637Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeToNameRegistrator0"::Berlin::0
2023-01-24T10:15:50.326639Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistrator0.json"
2023-01-24T10:15:50.326642Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:50.326643Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:50.326748Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-01-24T10:15:50.326753Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=106): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:50.326762Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:50.326765Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeToNameRegistrator0"::London::0
2023-01-24T10:15:50.326767Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistrator0.json"
2023-01-24T10:15:50.326770Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:50.326771Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:50.326860Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-01-24T10:15:50.326864Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=106): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:50.326872Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:50.326875Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeToNameRegistrator0"::Merge::0
2023-01-24T10:15:50.326877Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistrator0.json"
2023-01-24T10:15:50.326880Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:50.326881Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:50.326968Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-01-24T10:15:50.326973Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=106): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:50.327543Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistrator0.json"
2023-01-24T10:15:50.327570Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorAddresTooBigLeft.json"
2023-01-24T10:15:50.351945Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:50.352057Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:50.352062Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:50.352127Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:50.352129Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:15:50.352190Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:50.352277Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:50.352283Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeToNameRegistratorAddresTooBigLeft"::Istanbul::0
2023-01-24T10:15:50.352286Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorAddresTooBigLeft.json"
2023-01-24T10:15:50.352289Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:50.352291Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:50.691477Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551586,
    events_root: None,
}
2023-01-24T10:15:50.691493Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=107): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:50.691508Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:50.691516Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeToNameRegistratorAddresTooBigLeft"::Berlin::0
2023-01-24T10:15:50.691518Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorAddresTooBigLeft.json"
2023-01-24T10:15:50.691521Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:50.691523Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:50.691633Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551586,
    events_root: None,
}
2023-01-24T10:15:50.691639Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=107): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:50.691647Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:50.691650Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeToNameRegistratorAddresTooBigLeft"::London::0
2023-01-24T10:15:50.691652Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorAddresTooBigLeft.json"
2023-01-24T10:15:50.691655Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:50.691657Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:50.691759Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551586,
    events_root: None,
}
2023-01-24T10:15:50.691766Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=107): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:50.691777Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:50.691780Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeToNameRegistratorAddresTooBigLeft"::Merge::0
2023-01-24T10:15:50.691783Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorAddresTooBigLeft.json"
2023-01-24T10:15:50.691786Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:50.691788Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:50.691897Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551586,
    events_root: None,
}
2023-01-24T10:15:50.691903Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=107): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:50.692651Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorAddresTooBigLeft.json"
2023-01-24T10:15:50.692681Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorAddresTooBigRight.json"
2023-01-24T10:15:50.717635Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:50.717752Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:50.717756Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:50.717815Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:50.717817Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:15:50.717880Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:50.717958Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:50.717966Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeToNameRegistratorAddresTooBigRight"::Istanbul::0
2023-01-24T10:15:50.717970Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorAddresTooBigRight.json"
2023-01-24T10:15:50.717974Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:50.717976Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:51.067258Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551586,
    events_root: None,
}
2023-01-24T10:15:51.067278Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=107): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:51.067292Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:51.067303Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeToNameRegistratorAddresTooBigRight"::Berlin::0
2023-01-24T10:15:51.067305Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorAddresTooBigRight.json"
2023-01-24T10:15:51.067309Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:51.067310Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:51.067448Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551586,
    events_root: None,
}
2023-01-24T10:15:51.067453Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=107): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:51.067466Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:51.067469Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeToNameRegistratorAddresTooBigRight"::London::0
2023-01-24T10:15:51.067473Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorAddresTooBigRight.json"
2023-01-24T10:15:51.067477Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:51.067479Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:51.067573Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551586,
    events_root: None,
}
2023-01-24T10:15:51.067579Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=107): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:51.067590Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:51.067594Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeToNameRegistratorAddresTooBigRight"::Merge::0
2023-01-24T10:15:51.067596Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorAddresTooBigRight.json"
2023-01-24T10:15:51.067600Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:51.067602Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:51.067706Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551586,
    events_root: None,
}
2023-01-24T10:15:51.067712Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=107): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:51.068510Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorAddresTooBigRight.json"
2023-01-24T10:15:51.068540Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorZeroMemExpanion.json"
2023-01-24T10:15:51.093069Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:51.093179Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:51.093183Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:51.093240Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:51.093242Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:15:51.093306Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:51.093381Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:51.093387Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::Istanbul::0
2023-01-24T10:15:51.093391Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorZeroMemExpanion.json"
2023-01-24T10:15:51.093396Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:51.093398Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:51.427000Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-01-24T10:15:51.427020Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=106): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:51.427034Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:51.427040Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::Istanbul::0
2023-01-24T10:15:51.427043Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorZeroMemExpanion.json"
2023-01-24T10:15:51.427046Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:51.427047Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:51.427174Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-01-24T10:15:51.427179Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=106): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:51.427188Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:51.427191Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::Berlin::0
2023-01-24T10:15:51.427193Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorZeroMemExpanion.json"
2023-01-24T10:15:51.427196Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:51.427198Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:51.427286Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-01-24T10:15:51.427291Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=106): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:51.427300Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:51.427302Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::Berlin::0
2023-01-24T10:15:51.427304Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorZeroMemExpanion.json"
2023-01-24T10:15:51.427307Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:51.427308Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:51.427399Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-01-24T10:15:51.427405Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=106): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:51.427415Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:51.427418Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::London::0
2023-01-24T10:15:51.427420Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorZeroMemExpanion.json"
2023-01-24T10:15:51.427424Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:51.427425Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:51.427512Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-01-24T10:15:51.427517Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=106): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:51.427527Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:51.427529Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::London::0
2023-01-24T10:15:51.427532Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorZeroMemExpanion.json"
2023-01-24T10:15:51.427535Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:51.427536Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:51.427622Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-01-24T10:15:51.427626Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=106): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:51.427635Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:51.427638Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::Merge::0
2023-01-24T10:15:51.427640Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorZeroMemExpanion.json"
2023-01-24T10:15:51.427642Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:51.427644Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:51.427740Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-01-24T10:15:51.427745Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=106): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:51.427753Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:51.427756Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeToNameRegistratorZeroMemExpanion"::Merge::0
2023-01-24T10:15:51.427758Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorZeroMemExpanion.json"
2023-01-24T10:15:51.427761Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:51.427763Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:51.427849Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-01-24T10:15:51.427854Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=106): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:51.428466Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToNameRegistratorZeroMemExpanion.json"
2023-01-24T10:15:51.428494Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToReturn1.json"
2023-01-24T10:15:51.452704Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:51.452819Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:51.452823Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:51.452877Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:51.452879Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:15:51.452939Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:51.453012Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:51.453018Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeToReturn1"::Istanbul::0
2023-01-24T10:15:51.453021Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToReturn1.json"
2023-01-24T10:15:51.453025Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:51.453027Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:51.794536Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-01-24T10:15:51.794553Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=106): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:51.794567Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:51.794574Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeToReturn1"::Berlin::0
2023-01-24T10:15:51.794576Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToReturn1.json"
2023-01-24T10:15:51.794578Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:51.794580Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:51.794686Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-01-24T10:15:51.794691Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=106): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:51.794700Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:51.794702Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeToReturn1"::London::0
2023-01-24T10:15:51.794704Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToReturn1.json"
2023-01-24T10:15:51.794707Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:51.794708Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:51.794796Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-01-24T10:15:51.794801Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=106): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:51.794809Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:51.794812Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callcodeToReturn1"::Merge::0
2023-01-24T10:15:51.794813Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToReturn1.json"
2023-01-24T10:15:51.794816Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:51.794817Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:51.794907Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 35,
    },
    return_data: RawBytes {  },
    gas_used: 1551631,
    events_root: None,
}
2023-01-24T10:15:51.794912Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 35,
                    },
                    message: "ABORT(pc=106): undefined instruction",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:51.795727Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callcodeToReturn1.json"
2023-01-24T10:15:51.795751Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callerAccountBalance.json"
2023-01-24T10:15:51.820010Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:51.820116Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:51.820120Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:51.820175Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:51.820247Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:51.820253Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callerAccountBalance"::Istanbul::0
2023-01-24T10:15:51.820256Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callerAccountBalance.json"
2023-01-24T10:15:51.820260Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:51.820262Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:52.189946Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2479617,
    events_root: None,
}
2023-01-24T10:15:52.189971Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:52.189977Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callerAccountBalance"::Berlin::0
2023-01-24T10:15:52.189980Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callerAccountBalance.json"
2023-01-24T10:15:52.189983Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:52.189984Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:52.190115Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1580630,
    events_root: None,
}
2023-01-24T10:15:52.190122Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:52.190125Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callerAccountBalance"::London::0
2023-01-24T10:15:52.190126Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callerAccountBalance.json"
2023-01-24T10:15:52.190129Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:52.190130Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:52.190220Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1580630,
    events_root: None,
}
2023-01-24T10:15:52.190226Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:52.190228Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "callerAccountBalance"::Merge::0
2023-01-24T10:15:52.190230Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callerAccountBalance.json"
2023-01-24T10:15:52.190233Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:52.190234Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:52.190321Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1580630,
    events_root: None,
}
2023-01-24T10:15:52.190991Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/callerAccountBalance.json"
2023-01-24T10:15:52.191018Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistrator.json"
2023-01-24T10:15:52.215571Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:52.215687Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:52.215690Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:52.215758Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:52.215853Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:52.215861Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistrator"::Istanbul::0
2023-01-24T10:15:52.215863Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistrator.json"
2023-01-24T10:15:52.215866Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:52.215868Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-24T10:15:52.861267Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14635493,
    events_root: None,
}
2023-01-24T10:15:52.861298Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:52.861305Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistrator"::Berlin::0
2023-01-24T10:15:52.861308Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistrator.json"
2023-01-24T10:15:52.861311Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:52.861313Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [184, 141, 232, 139, 53, 236, 191, 60, 20, 30, 60, 170, 226, 186, 243, 88, 52, 209, 143, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-01-24T10:15:52.861949Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13552078,
    events_root: None,
}
2023-01-24T10:15:52.861973Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:52.861977Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistrator"::London::0
2023-01-24T10:15:52.861979Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistrator.json"
2023-01-24T10:15:52.861982Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:52.861984Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [93, 53, 72, 12, 110, 127, 137, 82, 54, 63, 162, 128, 160, 169, 105, 6, 218, 152, 31, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-01-24T10:15:52.862565Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14470477,
    events_root: None,
}
2023-01-24T10:15:52.862585Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:52.862588Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistrator"::Merge::0
2023-01-24T10:15:52.862591Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistrator.json"
2023-01-24T10:15:52.862594Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:52.862595Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [91, 91, 211, 67, 161, 47, 180, 44, 98, 57, 10, 255, 99, 64, 181, 153, 71, 182, 2, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-01-24T10:15:52.863185Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14988249,
    events_root: None,
}
2023-01-24T10:15:52.864082Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistrator.json"
2023-01-24T10:15:52.864108Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOOG_MemExpansionOOV.json"
2023-01-24T10:15:52.888993Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:52.889104Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:52.889108Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:52.889166Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:52.889241Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:52.889246Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistratorOOG_MemExpansionOOV"::Istanbul::0
2023-01-24T10:15:52.889250Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOOG_MemExpansionOOV.json"
2023-01-24T10:15:52.889253Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:52.889255Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:53.237137Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1565742,
    events_root: None,
}
2023-01-24T10:15:53.237161Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:53.237169Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistratorOOG_MemExpansionOOV"::Berlin::0
2023-01-24T10:15:53.237173Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOOG_MemExpansionOOV.json"
2023-01-24T10:15:53.237176Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:53.237177Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:53.237311Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1565742,
    events_root: None,
}
2023-01-24T10:15:53.237320Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:53.237324Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistratorOOG_MemExpansionOOV"::London::0
2023-01-24T10:15:53.237327Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOOG_MemExpansionOOV.json"
2023-01-24T10:15:53.237332Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:53.237334Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:53.237447Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1565742,
    events_root: None,
}
2023-01-24T10:15:53.237455Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:53.237458Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistratorOOG_MemExpansionOOV"::Merge::0
2023-01-24T10:15:53.237460Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOOG_MemExpansionOOV.json"
2023-01-24T10:15:53.237464Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:53.237466Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:53.237571Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1565742,
    events_root: None,
}
2023-01-24T10:15:53.238413Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOOG_MemExpansionOOV.json"
2023-01-24T10:15:53.238439Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOutOfMemoryBonds0.json"
2023-01-24T10:15:53.262427Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:53.262530Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:53.262534Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:53.262588Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:53.262659Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:53.262664Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistratorOutOfMemoryBonds0"::Istanbul::0
2023-01-24T10:15:53.262667Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOutOfMemoryBonds0.json"
2023-01-24T10:15:53.262670Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:53.262672Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:53.627040Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1576598,
    events_root: None,
}
2023-01-24T10:15:53.627061Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=44): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:53.627076Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:53.627083Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistratorOutOfMemoryBonds0"::Berlin::0
2023-01-24T10:15:53.627085Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOutOfMemoryBonds0.json"
2023-01-24T10:15:53.627088Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:53.627089Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:53.627204Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1576598,
    events_root: None,
}
2023-01-24T10:15:53.627208Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=44): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:53.627217Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:53.627220Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistratorOutOfMemoryBonds0"::London::0
2023-01-24T10:15:53.627223Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOutOfMemoryBonds0.json"
2023-01-24T10:15:53.627225Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:53.627227Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:53.627319Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1576598,
    events_root: None,
}
2023-01-24T10:15:53.627323Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=44): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:53.627332Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:53.627334Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistratorOutOfMemoryBonds0"::Merge::0
2023-01-24T10:15:53.627336Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOutOfMemoryBonds0.json"
2023-01-24T10:15:53.627339Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:53.627341Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:53.627460Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1576598,
    events_root: None,
}
2023-01-24T10:15:53.627466Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=44): offset must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:53.628161Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOutOfMemoryBonds0.json"
2023-01-24T10:15:53.628187Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOutOfMemoryBonds1.json"
2023-01-24T10:15:53.652870Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:53.652979Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:53.652983Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:53.653039Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:53.653112Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:53.653119Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistratorOutOfMemoryBonds1"::Istanbul::0
2023-01-24T10:15:53.653122Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOutOfMemoryBonds1.json"
2023-01-24T10:15:53.653126Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:53.653127Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:54.000799Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1576354,
    events_root: None,
}
2023-01-24T10:15:54.000818Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=44): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:54.000833Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:54.000840Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistratorOutOfMemoryBonds1"::Berlin::0
2023-01-24T10:15:54.000842Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOutOfMemoryBonds1.json"
2023-01-24T10:15:54.000846Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:54.000847Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:54.000958Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1576354,
    events_root: None,
}
2023-01-24T10:15:54.000963Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=44): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:54.000973Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:54.000975Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistratorOutOfMemoryBonds1"::London::0
2023-01-24T10:15:54.000977Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOutOfMemoryBonds1.json"
2023-01-24T10:15:54.000980Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:54.000982Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:54.001076Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1576354,
    events_root: None,
}
2023-01-24T10:15:54.001081Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=44): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:54.001090Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:54.001092Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistratorOutOfMemoryBonds1"::Merge::0
2023-01-24T10:15:54.001094Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOutOfMemoryBonds1.json"
2023-01-24T10:15:54.001097Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:54.001099Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:54.001190Z  WARN evm_eth_compliance::statetest::runner: Execution Failed => Receipt {
    exit_code: ExitCode {
        value: 38,
    },
    return_data: RawBytes {  },
    gas_used: 1576354,
    events_root: None,
}
2023-01-24T10:15:54.001195Z  WARN evm_eth_compliance::statetest::runner: failure_info => Some(
    MessageBacktrace(
        Backtrace {
            frames: [
                Frame {
                    source: 400,
                    method: 3844450837,
                    code: ExitCode {
                        value: 38,
                    },
                    message: "ABORT(pc=44): size must be less than max u32",
                },
            ],
            cause: None,
        },
    ),
)
2023-01-24T10:15:54.001864Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorOutOfMemoryBonds1.json"
2023-01-24T10:15:54.001893Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorValueTooHigh.json"
2023-01-24T10:15:54.025510Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:54.025612Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:54.025615Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:54.025671Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:54.025744Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:54.025749Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistratorValueTooHigh"::Istanbul::0
2023-01-24T10:15:54.025754Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorValueTooHigh.json"
2023-01-24T10:15:54.025757Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:54.025759Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:54.368769Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1563369,
    events_root: None,
}
2023-01-24T10:15:54.368793Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:54.368801Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistratorValueTooHigh"::Berlin::0
2023-01-24T10:15:54.368805Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorValueTooHigh.json"
2023-01-24T10:15:54.368809Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:54.368811Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:54.368943Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1563369,
    events_root: None,
}
2023-01-24T10:15:54.368952Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:54.368955Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistratorValueTooHigh"::London::0
2023-01-24T10:15:54.368958Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorValueTooHigh.json"
2023-01-24T10:15:54.368962Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:54.368964Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:54.369059Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1563369,
    events_root: None,
}
2023-01-24T10:15:54.369067Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:54.369070Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistratorValueTooHigh"::Merge::0
2023-01-24T10:15:54.369073Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorValueTooHigh.json"
2023-01-24T10:15:54.369077Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:54.369079Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:54.369172Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1563369,
    events_root: None,
}
2023-01-24T10:15:54.369840Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorValueTooHigh.json"
2023-01-24T10:15:54.369871Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMem.json"
2023-01-24T10:15:54.393965Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:54.394075Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:54.394080Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:54.394139Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:54.394214Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:54.394220Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistratorZeroMem"::Istanbul::0
2023-01-24T10:15:54.394223Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMem.json"
2023-01-24T10:15:54.394228Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:54.394230Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-24T10:15:55.011109Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14574187,
    events_root: None,
}
2023-01-24T10:15:55.011144Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:55.011152Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistratorZeroMem"::Berlin::0
2023-01-24T10:15:55.011155Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMem.json"
2023-01-24T10:15:55.011159Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:55.011161Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [184, 141, 232, 139, 53, 236, 191, 60, 20, 30, 60, 170, 226, 186, 243, 88, 52, 209, 143, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-01-24T10:15:55.011870Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13489689,
    events_root: None,
}
2023-01-24T10:15:55.011891Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:55.011894Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistratorZeroMem"::London::0
2023-01-24T10:15:55.011896Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMem.json"
2023-01-24T10:15:55.011899Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:55.011900Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [93, 53, 72, 12, 110, 127, 137, 82, 54, 63, 162, 128, 160, 169, 105, 6, 218, 152, 31, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-01-24T10:15:55.012462Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14408087,
    events_root: None,
}
2023-01-24T10:15:55.012481Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:55.012485Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistratorZeroMem"::Merge::0
2023-01-24T10:15:55.012487Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMem.json"
2023-01-24T10:15:55.012491Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:55.012493Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [91, 91, 211, 67, 161, 47, 180, 44, 98, 57, 10, 255, 99, 64, 181, 153, 71, 182, 2, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-01-24T10:15:55.013084Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14925859,
    events_root: None,
}
2023-01-24T10:15:55.014082Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMem.json"
2023-01-24T10:15:55.014108Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMem2.json"
2023-01-24T10:15:55.038922Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:55.039026Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:55.039030Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:55.039086Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:55.039159Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:55.039165Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistratorZeroMem2"::Istanbul::0
2023-01-24T10:15:55.039168Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMem2.json"
2023-01-24T10:15:55.039171Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:55.039173Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-24T10:15:55.703397Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14575662,
    events_root: None,
}
2023-01-24T10:15:55.703432Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:55.703440Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistratorZeroMem2"::Berlin::0
2023-01-24T10:15:55.703443Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMem2.json"
2023-01-24T10:15:55.703446Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:55.703447Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [184, 141, 232, 139, 53, 236, 191, 60, 20, 30, 60, 170, 226, 186, 243, 88, 52, 209, 143, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-01-24T10:15:55.704225Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13491163,
    events_root: None,
}
2023-01-24T10:15:55.704248Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:55.704252Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistratorZeroMem2"::London::0
2023-01-24T10:15:55.704255Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMem2.json"
2023-01-24T10:15:55.704258Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:55.704260Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [93, 53, 72, 12, 110, 127, 137, 82, 54, 63, 162, 128, 160, 169, 105, 6, 218, 152, 31, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-01-24T10:15:55.704981Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14409562,
    events_root: None,
}
2023-01-24T10:15:55.705008Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:55.705013Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistratorZeroMem2"::Merge::0
2023-01-24T10:15:55.705016Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMem2.json"
2023-01-24T10:15:55.705019Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:55.705021Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [91, 91, 211, 67, 161, 47, 180, 44, 98, 57, 10, 255, 99, 64, 181, 153, 71, 182, 2, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-01-24T10:15:55.705807Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14927334,
    events_root: None,
}
2023-01-24T10:15:55.707008Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMem2.json"
2023-01-24T10:15:55.707035Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMemExpansion.json"
2023-01-24T10:15:55.732009Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:55.732120Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:55.732124Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:55.732181Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:55.732254Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:55.732259Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistratorZeroMemExpansion"::Istanbul::0
2023-01-24T10:15:55.732262Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMemExpansion.json"
2023-01-24T10:15:55.732267Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:55.732269Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-24T10:15:56.377566Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14574187,
    events_root: None,
}
2023-01-24T10:15:56.377601Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:56.377607Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistratorZeroMemExpansion"::Berlin::0
2023-01-24T10:15:56.377611Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMemExpansion.json"
2023-01-24T10:15:56.377614Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:56.377615Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [184, 141, 232, 139, 53, 236, 191, 60, 20, 30, 60, 170, 226, 186, 243, 88, 52, 209, 143, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-01-24T10:15:56.378262Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13489689,
    events_root: None,
}
2023-01-24T10:15:56.378282Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:56.378285Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistratorZeroMemExpansion"::London::0
2023-01-24T10:15:56.378287Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMemExpansion.json"
2023-01-24T10:15:56.378290Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:56.378292Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [93, 53, 72, 12, 110, 127, 137, 82, 54, 63, 162, 128, 160, 169, 105, 6, 218, 152, 31, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-01-24T10:15:56.378928Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14408087,
    events_root: None,
}
2023-01-24T10:15:56.378952Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:56.378955Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createNameRegistratorZeroMemExpansion"::Merge::0
2023-01-24T10:15:56.378957Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMemExpansion.json"
2023-01-24T10:15:56.378960Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:56.378962Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [91, 91, 211, 67, 161, 47, 180, 44, 98, 57, 10, 255, 99, 64, 181, 153, 71, 182, 2, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-01-24T10:15:56.379547Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 14925859,
    events_root: None,
}
2023-01-24T10:15:56.380745Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createNameRegistratorZeroMemExpansion.json"
2023-01-24T10:15:56.380773Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createWithInvalidOpcode.json"
2023-01-24T10:15:56.404868Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:56.404977Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:56.404980Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:56.405035Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:56.405107Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:56.405111Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createWithInvalidOpcode"::Istanbul::0
2023-01-24T10:15:56.405114Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createWithInvalidOpcode.json"
2023-01-24T10:15:56.405117Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:56.405119Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [210, 87, 22, 7, 226, 65, 236, 245, 144, 237, 148, 177, 45, 135, 201, 75, 171, 227, 109, 182, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
2023-01-24T10:15:57.039265Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13659830,
    events_root: None,
}
2023-01-24T10:15:57.039301Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:57.039310Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createWithInvalidOpcode"::Berlin::0
2023-01-24T10:15:57.039313Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createWithInvalidOpcode.json"
2023-01-24T10:15:57.039317Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:57.039319Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [184, 141, 232, 139, 53, 236, 191, 60, 20, 30, 60, 170, 226, 186, 243, 88, 52, 209, 143, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
2023-01-24T10:15:57.039961Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 12559237,
    events_root: None,
}
2023-01-24T10:15:57.039975Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:57.039978Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createWithInvalidOpcode"::London::0
2023-01-24T10:15:57.039980Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createWithInvalidOpcode.json"
2023-01-24T10:15:57.039983Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:57.039985Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [93, 53, 72, 12, 110, 127, 137, 82, 54, 63, 162, 128, 160, 169, 105, 6, 218, 152, 31, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
2023-01-24T10:15:57.040597Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13477452,
    events_root: None,
}
2023-01-24T10:15:57.040617Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:57.040620Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "createWithInvalidOpcode"::Merge::0
2023-01-24T10:15:57.040623Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createWithInvalidOpcode.json"
2023-01-24T10:15:57.040626Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:57.040627Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [91, 91, 211, 67, 161, 47, 180, 44, 98, 57, 10, 255, 99, 64, 181, 153, 71, 182, 2, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
2023-01-24T10:15:57.041213Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 13995224,
    events_root: None,
}
2023-01-24T10:15:57.042207Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/createWithInvalidOpcode.json"
2023-01-24T10:15:57.042238Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/currentAccountBalance.json"
2023-01-24T10:15:57.067185Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:57.067301Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:57.067305Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:57.067365Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:57.067440Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:57.067448Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "currentAccountBalance"::Istanbul::0
2023-01-24T10:15:57.067451Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/currentAccountBalance.json"
2023-01-24T10:15:57.067456Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:57.067458Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:57.438477Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2509963,
    events_root: None,
}
2023-01-24T10:15:57.438505Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:57.438515Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "currentAccountBalance"::Berlin::0
2023-01-24T10:15:57.438518Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/currentAccountBalance.json"
2023-01-24T10:15:57.438522Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:57.438524Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:57.438684Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1603601,
    events_root: None,
}
2023-01-24T10:15:57.438693Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:57.438696Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "currentAccountBalance"::London::0
2023-01-24T10:15:57.438698Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/currentAccountBalance.json"
2023-01-24T10:15:57.438701Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:57.438702Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:57.438827Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1603601,
    events_root: None,
}
2023-01-24T10:15:57.438836Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:57.438839Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "currentAccountBalance"::Merge::0
2023-01-24T10:15:57.438840Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/currentAccountBalance.json"
2023-01-24T10:15:57.438844Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:57.438845Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:57.438947Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1603601,
    events_root: None,
}
2023-01-24T10:15:57.439751Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/currentAccountBalance.json"
2023-01-24T10:15:57.439778Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTest.json"
2023-01-24T10:15:57.464127Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:57.464230Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:57.464234Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:57.464287Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:57.464359Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:57.464365Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "doubleSelfdestructTest"::Istanbul::0
2023-01-24T10:15:57.464367Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTest.json"
2023-01-24T10:15:57.464371Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:57.464372Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:57.810087Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 8688838,
    events_root: None,
}
2023-01-24T10:15:57.810114Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:57.810120Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "doubleSelfdestructTest"::Berlin::0
2023-01-24T10:15:57.810123Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTest.json"
2023-01-24T10:15:57.810126Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:57.810127Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:57.810208Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-24T10:15:57.810213Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:57.810216Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "doubleSelfdestructTest"::London::0
2023-01-24T10:15:57.810218Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTest.json"
2023-01-24T10:15:57.810220Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:57.810222Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:57.810288Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-24T10:15:57.810294Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:57.810296Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "doubleSelfdestructTest"::Merge::0
2023-01-24T10:15:57.810298Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTest.json"
2023-01-24T10:15:57.810300Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:57.810302Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:57.810365Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-24T10:15:57.811064Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTest.json"
2023-01-24T10:15:57.811095Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTest2.json"
2023-01-24T10:15:57.835543Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:57.835647Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:57.835651Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:57.835726Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:57.835802Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:57.835808Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "doubleSelfdestructTest2"::Istanbul::0
2023-01-24T10:15:57.835811Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTest2.json"
2023-01-24T10:15:57.835814Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:57.835816Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:58.173818Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 7674311,
    events_root: None,
}
2023-01-24T10:15:58.173843Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:58.173849Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "doubleSelfdestructTest2"::Berlin::0
2023-01-24T10:15:58.173853Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTest2.json"
2023-01-24T10:15:58.173856Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:58.173857Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:58.173941Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-24T10:15:58.173947Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:58.173950Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "doubleSelfdestructTest2"::London::0
2023-01-24T10:15:58.173952Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTest2.json"
2023-01-24T10:15:58.173955Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:58.173956Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:58.174024Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-24T10:15:58.174031Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:58.174034Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "doubleSelfdestructTest2"::Merge::0
2023-01-24T10:15:58.174036Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTest2.json"
2023-01-24T10:15:58.174038Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:58.174040Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:58.174105Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-24T10:15:58.174722Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTest2.json"
2023-01-24T10:15:58.174753Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTouch.json"
2023-01-24T10:15:58.199935Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:58.200042Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:58.200045Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:58.200106Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:58.200111Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:15:58.200174Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:58.200176Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 3
2023-01-24T10:15:58.200230Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:58.200233Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 4
2023-01-24T10:15:58.200286Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:58.200357Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:58.200363Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "doubleSelfdestructTouch"::London::0
2023-01-24T10:15:58.200366Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTouch.json"
2023-01-24T10:15:58.200369Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:58.200370Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:58.561297Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2031679,
    events_root: None,
}
2023-01-24T10:15:58.561320Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:58.561326Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "doubleSelfdestructTouch"::London::0
2023-01-24T10:15:58.561329Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTouch.json"
2023-01-24T10:15:58.561332Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:58.561334Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:58.561475Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2031679,
    events_root: None,
}
2023-01-24T10:15:58.561483Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:58.561485Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "doubleSelfdestructTouch"::London::0
2023-01-24T10:15:58.561487Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTouch.json"
2023-01-24T10:15:58.561490Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:58.561491Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:58.561620Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2031679,
    events_root: None,
}
2023-01-24T10:15:58.561628Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:58.561630Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "doubleSelfdestructTouch"::Merge::0
2023-01-24T10:15:58.561632Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTouch.json"
2023-01-24T10:15:58.561635Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:58.561637Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:58.561764Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2031679,
    events_root: None,
}
2023-01-24T10:15:58.561772Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:58.561774Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "doubleSelfdestructTouch"::Merge::0
2023-01-24T10:15:58.561776Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTouch.json"
2023-01-24T10:15:58.561779Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:58.561780Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:58.561904Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2031679,
    events_root: None,
}
2023-01-24T10:15:58.561912Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:58.561915Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "doubleSelfdestructTouch"::Merge::0
2023-01-24T10:15:58.561917Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTouch.json"
2023-01-24T10:15:58.561919Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:58.561921Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:58.562045Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2031679,
    events_root: None,
}
2023-01-24T10:15:58.562866Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/doubleSelfdestructTouch.json"
2023-01-24T10:15:58.562904Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/extcodecopy.json"
2023-01-24T10:15:58.590775Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:58.590877Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:58.590881Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:58.590936Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:58.590938Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 2
2023-01-24T10:15:58.590996Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:58.591072Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:58.591077Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodecopy"::Istanbul::0
2023-01-24T10:15:58.591080Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/extcodecopy.json"
2023-01-24T10:15:58.591083Z  INFO evm_eth_compliance::statetest::runner: TX len : 143
2023-01-24T10:15:58.591085Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:58.951596Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3615148,
    events_root: None,
}
2023-01-24T10:15:58.951619Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:58.951625Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodecopy"::Berlin::0
2023-01-24T10:15:58.951627Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/extcodecopy.json"
2023-01-24T10:15:58.951630Z  INFO evm_eth_compliance::statetest::runner: TX len : 143
2023-01-24T10:15:58.951632Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:58.951730Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1035599,
    events_root: None,
}
2023-01-24T10:15:58.951737Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:58.951740Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodecopy"::London::0
2023-01-24T10:15:58.951742Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/extcodecopy.json"
2023-01-24T10:15:58.951745Z  INFO evm_eth_compliance::statetest::runner: TX len : 143
2023-01-24T10:15:58.951746Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:58.951817Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1035599,
    events_root: None,
}
2023-01-24T10:15:58.951822Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:58.951825Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "extcodecopy"::Merge::0
2023-01-24T10:15:58.951829Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/extcodecopy.json"
2023-01-24T10:15:58.951831Z  INFO evm_eth_compliance::statetest::runner: TX len : 143
2023-01-24T10:15:58.951833Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:58.951906Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1035599,
    events_root: None,
}
2023-01-24T10:15:58.952546Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/extcodecopy.json"
2023-01-24T10:15:58.952572Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return0.json"
2023-01-24T10:15:58.976981Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:58.977081Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:58.977084Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:58.977138Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:58.977209Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:58.977213Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "return0"::Istanbul::0
2023-01-24T10:15:58.977216Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return0.json"
2023-01-24T10:15:58.977219Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:58.977220Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:59.318090Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 4137 },
    gas_used: 1536332,
    events_root: None,
}
2023-01-24T10:15:59.318111Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:59.318119Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "return0"::Berlin::0
2023-01-24T10:15:59.318122Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return0.json"
2023-01-24T10:15:59.318126Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:59.318127Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:59.318235Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 4137 },
    gas_used: 1536332,
    events_root: None,
}
2023-01-24T10:15:59.318243Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:59.318246Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "return0"::London::0
2023-01-24T10:15:59.318249Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return0.json"
2023-01-24T10:15:59.318252Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:59.318254Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:59.318344Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 4137 },
    gas_used: 1536332,
    events_root: None,
}
2023-01-24T10:15:59.318352Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:59.318355Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "return0"::Merge::0
2023-01-24T10:15:59.318357Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return0.json"
2023-01-24T10:15:59.318360Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:59.318362Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:59.318452Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 4137 },
    gas_used: 1536332,
    events_root: None,
}
2023-01-24T10:15:59.319194Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return0.json"
2023-01-24T10:15:59.319222Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return1.json"
2023-01-24T10:15:59.342959Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:59.343088Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:59.343093Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:59.343164Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:59.343260Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:59.343267Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "return1"::Istanbul::0
2023-01-24T10:15:59.343271Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return1.json"
2023-01-24T10:15:59.343278Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:59.343280Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:59.684785Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 423700 },
    gas_used: 1537643,
    events_root: None,
}
2023-01-24T10:15:59.684808Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:15:59.684815Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "return1"::Berlin::0
2023-01-24T10:15:59.684818Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return1.json"
2023-01-24T10:15:59.684821Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:59.684822Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:59.684947Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 423700 },
    gas_used: 1537643,
    events_root: None,
}
2023-01-24T10:15:59.684954Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:15:59.684957Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "return1"::London::0
2023-01-24T10:15:59.684959Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return1.json"
2023-01-24T10:15:59.684961Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:59.684962Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:59.685047Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 423700 },
    gas_used: 1537643,
    events_root: None,
}
2023-01-24T10:15:59.685054Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:15:59.685057Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "return1"::Merge::0
2023-01-24T10:15:59.685058Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return1.json"
2023-01-24T10:15:59.685061Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:59.685062Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:15:59.685146Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 423700 },
    gas_used: 1537643,
    events_root: None,
}
2023-01-24T10:15:59.685795Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return1.json"
2023-01-24T10:15:59.685821Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return2.json"
2023-01-24T10:15:59.710101Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:15:59.710208Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:59.710211Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:15:59.710268Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:15:59.710340Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:15:59.710345Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "return2"::Istanbul::0
2023-01-24T10:15:59.710348Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return2.json"
2023-01-24T10:15:59.710351Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:15:59.710352Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:16:00.068464Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5821370000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 1584985,
    events_root: None,
}
2023-01-24T10:16:00.068492Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:16:00.068498Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "return2"::Berlin::0
2023-01-24T10:16:00.068502Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return2.json"
2023-01-24T10:16:00.068505Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:16:00.068506Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:16:00.068680Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5821370000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 1584985,
    events_root: None,
}
2023-01-24T10:16:00.068692Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:16:00.068698Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "return2"::London::0
2023-01-24T10:16:00.068700Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return2.json"
2023-01-24T10:16:00.068704Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:16:00.068706Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:16:00.068817Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5821370000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 1584985,
    events_root: None,
}
2023-01-24T10:16:00.068826Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:16:00.068829Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "return2"::Merge::0
2023-01-24T10:16:00.068831Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return2.json"
2023-01-24T10:16:00.068833Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:16:00.068835Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:16:00.068923Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 5821370000000000000000000000000000000000000000000000000000000000000000 },
    gas_used: 1584985,
    events_root: None,
}
2023-01-24T10:16:00.069769Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/return2.json"
2023-01-24T10:16:00.069804Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideAddress.json"
2023-01-24T10:16:00.094325Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:16:00.094428Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:16:00.094432Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:16:00.094487Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:16:00.094559Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:16:00.094564Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideAddress"::Istanbul::0
2023-01-24T10:16:00.094567Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideAddress.json"
2023-01-24T10:16:00.094570Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:16:00.094571Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:16:00.466467Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2746611,
    events_root: None,
}
2023-01-24T10:16:00.466492Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:16:00.466498Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideAddress"::Berlin::0
2023-01-24T10:16:00.466501Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideAddress.json"
2023-01-24T10:16:00.466504Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:16:00.466506Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:16:00.466606Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-24T10:16:00.466613Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:16:00.466615Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideAddress"::London::0
2023-01-24T10:16:00.466617Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideAddress.json"
2023-01-24T10:16:00.466619Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:16:00.466621Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:16:00.466691Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-24T10:16:00.466697Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:16:00.466699Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideAddress"::Merge::0
2023-01-24T10:16:00.466701Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideAddress.json"
2023-01-24T10:16:00.466704Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:16:00.466705Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:16:00.466771Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-24T10:16:00.467516Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideAddress.json"
2023-01-24T10:16:00.467541Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCaller.json"
2023-01-24T10:16:00.491342Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:16:00.491448Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:16:00.491451Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:16:00.491508Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:16:00.491579Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:16:00.491583Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideCaller"::Istanbul::0
2023-01-24T10:16:00.491586Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCaller.json"
2023-01-24T10:16:00.491589Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:16:00.491592Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:16:00.861727Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2743390,
    events_root: None,
}
2023-01-24T10:16:00.861749Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:16:00.861756Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideCaller"::Berlin::0
2023-01-24T10:16:00.861759Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCaller.json"
2023-01-24T10:16:00.861762Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:16:00.861763Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:16:00.861872Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-24T10:16:00.861879Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:16:00.861882Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideCaller"::London::0
2023-01-24T10:16:00.861884Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCaller.json"
2023-01-24T10:16:00.861887Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:16:00.861889Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:16:00.861959Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-24T10:16:00.861965Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:16:00.861968Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideCaller"::Merge::0
2023-01-24T10:16:00.861969Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCaller.json"
2023-01-24T10:16:00.861972Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:16:00.861973Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:16:00.862042Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-24T10:16:00.862661Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCaller.json"
2023-01-24T10:16:00.862687Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCallerAddresTooBigLeft.json"
2023-01-24T10:16:00.887456Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:16:00.887559Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:16:00.887562Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:16:00.887617Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:16:00.887700Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:16:00.887705Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideCallerAddresTooBigLeft"::Istanbul::0
2023-01-24T10:16:00.887708Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCallerAddresTooBigLeft.json"
2023-01-24T10:16:00.887711Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:16:00.887713Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:16:01.250992Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2753817,
    events_root: None,
}
2023-01-24T10:16:01.251016Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:16:01.251024Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideCallerAddresTooBigLeft"::Berlin::0
2023-01-24T10:16:01.251027Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCallerAddresTooBigLeft.json"
2023-01-24T10:16:01.251030Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:16:01.251031Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:16:01.251118Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-24T10:16:01.251124Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:16:01.251126Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideCallerAddresTooBigLeft"::London::0
2023-01-24T10:16:01.251128Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCallerAddresTooBigLeft.json"
2023-01-24T10:16:01.251131Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:16:01.251132Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:16:01.251199Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-24T10:16:01.251206Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:16:01.251209Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideCallerAddresTooBigLeft"::Merge::0
2023-01-24T10:16:01.251211Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCallerAddresTooBigLeft.json"
2023-01-24T10:16:01.251214Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:16:01.251215Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:16:01.251280Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-24T10:16:01.251997Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCallerAddresTooBigLeft.json"
2023-01-24T10:16:01.252027Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCallerAddresTooBigRight.json"
2023-01-24T10:16:01.275953Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:16:01.276061Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:16:01.276064Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:16:01.276119Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:16:01.276191Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:16:01.276195Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideCallerAddresTooBigRight"::Istanbul::0
2023-01-24T10:16:01.276198Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCallerAddresTooBigRight.json"
2023-01-24T10:16:01.276202Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:16:01.276203Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:16:01.627839Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3961071,
    events_root: None,
}
2023-01-24T10:16:01.627861Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:16:01.627869Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideCallerAddresTooBigRight"::Berlin::0
2023-01-24T10:16:01.627872Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCallerAddresTooBigRight.json"
2023-01-24T10:16:01.627876Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:16:01.627878Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:16:01.627968Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-24T10:16:01.627975Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:16:01.627978Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideCallerAddresTooBigRight"::London::0
2023-01-24T10:16:01.627981Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCallerAddresTooBigRight.json"
2023-01-24T10:16:01.627985Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:16:01.627987Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:16:01.628058Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-24T10:16:01.628067Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:16:01.628070Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideCallerAddresTooBigRight"::Merge::0
2023-01-24T10:16:01.628073Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCallerAddresTooBigRight.json"
2023-01-24T10:16:01.628077Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:16:01.628079Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:16:01.628148Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-24T10:16:01.628782Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideCallerAddresTooBigRight.json"
2023-01-24T10:16:01.628811Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideNotExistingAccount.json"
2023-01-24T10:16:01.652574Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:16:01.652681Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:16:01.652686Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:16:01.652743Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:16:01.652816Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:16:01.652821Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideNotExistingAccount"::Istanbul::0
2023-01-24T10:16:01.652825Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideNotExistingAccount.json"
2023-01-24T10:16:01.652829Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:16:01.652831Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:16:02.021074Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 3551438,
    events_root: None,
}
2023-01-24T10:16:02.021096Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:16:02.021103Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideNotExistingAccount"::Berlin::0
2023-01-24T10:16:02.021106Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideNotExistingAccount.json"
2023-01-24T10:16:02.021109Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:16:02.021111Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:16:02.021228Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-24T10:16:02.021238Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:16:02.021241Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideNotExistingAccount"::London::0
2023-01-24T10:16:02.021244Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideNotExistingAccount.json"
2023-01-24T10:16:02.021248Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:16:02.021250Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:16:02.021339Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-24T10:16:02.021346Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:16:02.021350Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideNotExistingAccount"::Merge::0
2023-01-24T10:16:02.021353Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideNotExistingAccount.json"
2023-01-24T10:16:02.021357Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:16:02.021359Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:16:02.021430Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-24T10:16:02.022117Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideNotExistingAccount.json"
2023-01-24T10:16:02.022146Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideOrigin.json"
2023-01-24T10:16:02.047807Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:16:02.047937Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:16:02.047941Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:16:02.048011Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:16:02.048108Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:16:02.048116Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideOrigin"::Istanbul::0
2023-01-24T10:16:02.048120Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideOrigin.json"
2023-01-24T10:16:02.048124Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:16:02.048126Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:16:02.426387Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2773962,
    events_root: None,
}
2023-01-24T10:16:02.426409Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:16:02.426417Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideOrigin"::Berlin::0
2023-01-24T10:16:02.426420Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideOrigin.json"
2023-01-24T10:16:02.426423Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:16:02.426425Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:16:02.426531Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-24T10:16:02.426537Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:16:02.426540Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideOrigin"::London::0
2023-01-24T10:16:02.426542Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideOrigin.json"
2023-01-24T10:16:02.426544Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:16:02.426546Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:16:02.426611Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-24T10:16:02.426617Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:16:02.426619Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideOrigin"::Merge::0
2023-01-24T10:16:02.426621Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideOrigin.json"
2023-01-24T10:16:02.426624Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:16:02.426625Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:16:02.426688Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-24T10:16:02.427568Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideOrigin.json"
2023-01-24T10:16:02.427596Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideSendEtherPostDeath.json"
2023-01-24T10:16:02.452292Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:16:02.452398Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:16:02.452401Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:16:02.452455Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:16:02.452528Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:16:02.452533Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideSendEtherPostDeath"::Istanbul::0
2023-01-24T10:16:02.452536Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideSendEtherPostDeath.json"
2023-01-24T10:16:02.452540Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-24T10:16:02.452541Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:16:02.823091Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 58200000000000000000000000000000000000000000000000000de0b6b3a7640000 },
    gas_used: 4955857,
    events_root: None,
}
2023-01-24T10:16:02.823122Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:16:02.823129Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideSendEtherPostDeath"::Berlin::0
2023-01-24T10:16:02.823132Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideSendEtherPostDeath.json"
2023-01-24T10:16:02.823136Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-24T10:16:02.823138Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:16:02.823226Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1035837,
    events_root: None,
}
2023-01-24T10:16:02.823232Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:16:02.823235Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideSendEtherPostDeath"::London::0
2023-01-24T10:16:02.823237Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideSendEtherPostDeath.json"
2023-01-24T10:16:02.823239Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-24T10:16:02.823241Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:16:02.823309Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1035837,
    events_root: None,
}
2023-01-24T10:16:02.823315Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:16:02.823318Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideSendEtherPostDeath"::Merge::0
2023-01-24T10:16:02.823320Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideSendEtherPostDeath.json"
2023-01-24T10:16:02.823323Z  INFO evm_eth_compliance::statetest::runner: TX len : 4
2023-01-24T10:16:02.823324Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:16:02.823390Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1035837,
    events_root: None,
}
2023-01-24T10:16:02.824093Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideSendEtherPostDeath.json"
2023-01-24T10:16:02.824121Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideSendEtherToMe.json"
2023-01-24T10:16:02.848013Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:16:02.848115Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:16:02.848119Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:16:02.848172Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:16:02.848245Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:16:02.848250Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideSendEtherToMe"::Istanbul::0
2023-01-24T10:16:02.848253Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideSendEtherToMe.json"
2023-01-24T10:16:02.848256Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:16:02.848257Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:16:03.210965Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 2339024,
    events_root: None,
}
2023-01-24T10:16:03.210990Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:16:03.210997Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideSendEtherToMe"::Berlin::0
2023-01-24T10:16:03.211000Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideSendEtherToMe.json"
2023-01-24T10:16:03.211003Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:16:03.211005Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:16:03.211093Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-24T10:16:03.211100Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:16:03.211103Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideSendEtherToMe"::London::0
2023-01-24T10:16:03.211105Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideSendEtherToMe.json"
2023-01-24T10:16:03.211107Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:16:03.211108Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:16:03.211194Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-24T10:16:03.211202Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:16:03.211205Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "suicideSendEtherToMe"::Merge::0
2023-01-24T10:16:03.211208Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideSendEtherToMe.json"
2023-01-24T10:16:03.211212Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:16:03.211214Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
2023-01-24T10:16:03.211302Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 1034122,
    events_root: None,
}
2023-01-24T10:16:03.212007Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/suicideSendEtherToMe.json"
2023-01-24T10:16:03.212037Z TRACE evm_eth_compliance::statetest::runner: Calling testfile => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/testRandomTest.json"
2023-01-24T10:16:03.236801Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 0
2023-01-24T10:16:03.236907Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:16:03.236910Z  INFO evm_eth_compliance::statetest::runner: Pre-Block Iteration :: 1
2023-01-24T10:16:03.236966Z  INFO evm_eth_compliance::statetest::runner: New State ID Updated
2023-01-24T10:16:03.237039Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Istanbul 0
2023-01-24T10:16:03.237043Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "testRandomTest"::Istanbul::0
2023-01-24T10:16:03.237046Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/testRandomTest.json"
2023-01-24T10:16:03.237049Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:16:03.237051Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [148, 83, 4, 235, 150, 6, 91, 42, 152, 181, 122, 72, 160, 106, 226, 141, 40, 90, 113, 181, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([215, 166, 242, 208, 200, 186, 79, 10, 126, 8, 221, 102, 9, 12, 200, 158, 203, 19, 78, 227]) }
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [235, 204, 229, 246, 5, 48, 39, 94, 233, 49, 140, 225, 239, 249, 228, 191, 238, 129, 1, 114, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([178, 136, 95, 13, 181, 217, 120, 204, 197, 243, 155, 145, 50, 151, 43, 92, 167, 175, 132, 25]) }
2023-01-24T10:16:03.904321Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 25501864,
    events_root: None,
}
2023-01-24T10:16:03.904358Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Berlin 0
2023-01-24T10:16:03.904364Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "testRandomTest"::Berlin::0
2023-01-24T10:16:03.904367Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/testRandomTest.json"
2023-01-24T10:16:03.904370Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:16:03.904371Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [52, 206, 105, 18, 180, 86, 169, 134, 66, 145, 242, 213, 71, 127, 184, 201, 186, 98, 26, 247, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([67, 35, 255, 1, 46, 226, 200, 90, 20, 150, 237, 153, 222, 171, 201, 9, 99, 31, 101, 211]) }
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [99, 146, 186, 46, 153, 226, 84, 67, 25, 239, 102, 183, 123, 143, 110, 42, 204, 247, 6, 193, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([239, 242, 33, 137, 111, 16, 15, 190, 235, 110, 77, 4, 63, 5, 41, 98, 192, 28, 206, 35]) }
2023-01-24T10:16:03.905347Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 25494214,
    events_root: None,
}
2023-01-24T10:16:03.905373Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => London 0
2023-01-24T10:16:03.905376Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "testRandomTest"::London::0
2023-01-24T10:16:03.905378Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/testRandomTest.json"
2023-01-24T10:16:03.905380Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:16:03.905383Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [150, 151, 1, 50, 14, 235, 234, 97, 11, 211, 47, 136, 169, 204, 9, 15, 76, 88, 177, 216, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([28, 35, 125, 168, 212, 11, 234, 180, 81, 129, 48, 219, 76, 10, 52, 89, 217, 159, 194, 2]) }
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [175, 233, 83, 17, 74, 10, 5, 74, 134, 230, 192, 174, 6, 155, 136, 139, 118, 51, 127, 235, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([234, 24, 246, 14, 245, 153, 41, 227, 62, 255, 40, 203, 90, 71, 156, 92, 203, 241, 198, 169]) }
2023-01-24T10:16:03.906329Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 25635545,
    events_root: None,
}
2023-01-24T10:16:03.906355Z  INFO evm_eth_compliance::statetest::runner: Entering Post Block => Merge 0
2023-01-24T10:16:03.906358Z  INFO evm_eth_compliance::statetest::runner: Executing TestCase "testRandomTest"::Merge::0
2023-01-24T10:16:03.906360Z  INFO evm_eth_compliance::statetest::runner: Path : "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/testRandomTest.json"
2023-01-24T10:16:03.906363Z  INFO evm_eth_compliance::statetest::runner: TX len : 0
2023-01-24T10:16:03.906365Z  INFO evm_eth_compliance::statetest::runner: Tracing Status : true
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [164, 159, 137, 55, 107, 23, 23, 172, 189, 110, 149, 242, 218, 194, 80, 151, 112, 7, 220, 136, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([132, 105, 76, 107, 184, 77, 78, 105, 101, 219, 134, 121, 221, 254, 217, 203, 72, 121, 220, 83]) }
[TRACE] delegated address: Address { payload: Delegated(DelegatedAddress { namespace: 10, length: 20, buffer: [80, 136, 160, 236, 60, 241, 52, 128, 198, 110, 1, 228, 88, 211, 42, 243, 36, 124, 156, 111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }) }
[TRACE] robust address: Address { payload: Actor([217, 138, 9, 115, 71, 212, 34, 51, 81, 252, 105, 199, 181, 39, 187, 149, 48, 141, 211, 216]) }
2023-01-24T10:16:03.907310Z  INFO evm_eth_compliance::statetest::runner: Execution Success => Receipt {
    exit_code: ExitCode {
        value: 0,
    },
    return_data: RawBytes { 40 },
    gas_used: 25899689,
    events_root: None,
}
2023-01-24T10:16:03.908319Z TRACE evm_eth_compliance::statetest::runner: TestDone => "test-vectors/tests/GeneralStateTests/stSystemOperationsTest/testRandomTest.json"
2023-01-24T10:16:03.908899Z  INFO evm_eth_compliance::statetest::runner: Finished Processing of 67 Files in Time:30.046921429s
```